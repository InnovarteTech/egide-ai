<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\User;
use App\Security\ApiOracles;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class RunScanOraclesTest extends TestCase
{
    use RefreshDatabase;

    private function invokePrivate(string $method, array $args)
    {
        $job = new RunScan('x');
        $ref = new \ReflectionMethod($job, $method);
        $ref->setAccessible(true);

        return $ref->invoke($job, ...$args);
    }

    private function invokePrivate2(RunScan $job, string $method, array $args): void
    {
        $ref = new \ReflectionMethod($job, $method);
        $ref->setAccessible(true);
        $ref->invoke($job, ...$args);
    }

    public function test_bfla_confirmed_and_protected(): void
    {
        $admin = ['status' => 200, 'marker' => 'EGIDE-ADMIN0000'];

        $leak = $this->invokePrivate('bflaAssess', ['GET', '/admin/relatorio', $admin, ['status' => 200, 'marker' => 'EGIDE-ADMIN0000']]);
        $this->assertSame('falha', $leak['verdict']);
        $this->assertNotNull($leak['finding']);
        $this->assertSame('critical', $leak['finding']['severity']);
        $this->assertSame('BFLA · autorização por função', $leak['finding']['category']);
        $this->assertTrue($leak['finding']['evidence']['marker_verified']);
        $this->assertSame('/admin/relatorio', $leak['finding']['evidence']['path']);

        $denied = $this->invokePrivate('bflaAssess', ['GET', '/admin/relatorio', $admin, ['status' => 403]]);
        $this->assertSame('protegido', $denied['verdict']);
        $this->assertNull($denied['finding']);

        // Our own proxy blocked the probe (budget/scope) → cannot conclude, NOT "protegido".
        $blocked = $this->invokePrivate('bflaAssess', ['GET', '/admin/relatorio', $admin, ['status' => 403, 'blocked' => true]]);
        $this->assertSame('nao_testado', $blocked['verdict']);

        // Review Focus #3: 200 without the privileged marker (public-ish page) is NOT a BFLA finding.
        $publicish = $this->invokePrivate('bflaAssess', ['GET', '/admin/relatorio', $admin, ['status' => 200, 'marker' => null]]);
        $this->assertSame('protegido', $publicish['verdict']);
        $this->assertNull($publicish['finding']);

        // Route the admin never proved privileged (no marker) cannot yield a verdict.
        $unknown = $this->invokePrivate('bflaAssess', ['GET', '/admin/relatorio', ['status' => 500], ['status' => 200, 'marker' => 'x']]);
        $this->assertSame('nao_testado', $unknown['verdict']);
    }

    public function test_unauth_access_confirmed_and_protected(): void
    {
        $auth = ['status' => 200, 'marker' => 'EGIDE-PROT000AAA'];

        $leak = $this->invokePrivate('unauthAssess', ['GET', '/painel/dados', $auth, ['status' => 200, 'marker' => 'EGIDE-PROT000AAA']]);
        $this->assertSame('falha', $leak['verdict']);
        $this->assertNotNull($leak['finding']);
        $this->assertSame('high', $leak['finding']['severity']);
        $this->assertSame('Acesso sem autenticação', $leak['finding']['category']);
        $this->assertSame(200, $leak['finding']['evidence']['anon_status']);
        $this->assertTrue($leak['finding']['evidence']['same_data']);

        $denied = $this->invokePrivate('unauthAssess', ['GET', '/painel/dados', $auth, ['status' => 401]]);
        $this->assertSame('protegido', $denied['verdict']);
        $this->assertNull($denied['finding']);

        $blocked = $this->invokePrivate('unauthAssess', ['GET', '/painel/dados', $auth, ['status' => 403, 'blocked' => true]]);
        $this->assertSame('nao_testado', $blocked['verdict']);

        // Review Focus #4: anon 200 but DIFFERENT data (login page, public home) is not a leak.
        $publicPage = $this->invokePrivate('unauthAssess', ['GET', '/painel/dados', $auth, ['status' => 200, 'marker' => null]]);
        $this->assertSame('protegido', $publicPage['verdict']);
        $this->assertNull($publicPage['finding']);

        $noBaseline = $this->invokePrivate('unauthAssess', ['GET', '/painel/dados', ['status' => 500], ['status' => 200, 'marker' => 'x']]);
        $this->assertSame('nao_testado', $noBaseline['verdict']);
    }

    public function test_id_enumeration_reads_other_record(): void
    {
        $plan = $this->invokePrivate('idEnumCandidates', ['/bookings/12']);
        $this->assertSame(12, $plan['own_id']);
        $this->assertSame('/bookings/{id}', $plan['base_path']);
        $this->assertArrayHasKey(11, $plan['paths']);
        $this->assertArrayHasKey(13, $plan['paths']);
        $this->assertSame('/bookings/11', $plan['paths'][11]);
        $this->assertLessThanOrEqual(5, count($plan['paths']));
        $this->assertArrayNotHasKey(12, $plan['paths']);

        $this->assertNull($this->invokePrivate('idEnumCandidates', ['/servicos/home']));
        $apiPlan = $this->invokePrivate('idEnumCandidates', ['https://api.example.com/pedidos/34']);
        $this->assertSame('https://api.example.com/pedidos/33', $apiPlan['paths'][33]);

        $cross = $this->invokePrivate('idEnumAssess', ['/bookings/{id}', 12, 11, ['status' => 200, 'marker' => 'EGIDE-OTHER00000'], 'EGIDE-MINE000000']);
        $this->assertSame('falha', $cross['verdict']);
        $this->assertSame('high', $cross['finding']['severity']);
        $this->assertSame('IDOR · enumeração de ID', $cross['finding']['category']);
        $this->assertSame(11, $cross['finding']['evidence']['probed_id']);
        $this->assertSame('EGIDE-OTHER00000', $cross['finding']['evidence']['cross_marker']);

        $ownAgain = $this->invokePrivate('idEnumAssess', ['/bookings/{id}', 12, 11, ['status' => 200, 'marker' => 'EGIDE-MINE000000'], 'EGIDE-MINE000000']);
        $this->assertSame('protegido', $ownAgain['verdict']);
        $this->assertNull($ownAgain['finding']);

        $blocked = $this->invokePrivate('idEnumAssess', ['/bookings/{id}', 12, 11, ['status' => 404], 'EGIDE-MINE000000']);
        $this->assertSame('protegido', $blocked['verdict']);

        $proxyBlocked = $this->invokePrivate('idEnumAssess', ['/bookings/{id}', 12, 11, ['status' => 403, 'blocked' => true], 'EGIDE-MINE000000']);
        $this->assertSame('nao_testado', $proxyBlocked['verdict']);
    }

    public function test_cover_collects_rows_per_check_and_route(): void
    {
        $job = new RunScan('x');
        $this->invokePrivate2($job, 'cover', ['BFLA', '/admin/relatorio', 'falha']);
        $this->invokePrivate2($job, 'cover', ['Acesso sem autenticação', '/painel', 'protegido']);
        $prop = new \ReflectionProperty($job, 'coverage');
        $prop->setAccessible(true);
        $rows = $prop->getValue($job);
        $this->assertSame([
            ['check' => 'BFLA', 'route' => '/admin/relatorio', 'verdict' => 'falha'],
            ['check' => 'Acesso sem autenticação', 'route' => '/painel', 'verdict' => 'protegido'],
        ], $rows);
    }

    public function test_coverage_map_records_verdicts(): void
    {
        $user = User::factory()->create();
        $scan = Scan::create([
            'user_id' => $user->id, 'name' => 'Laboratório', 'mode' => 'laboratory',
            'scope' => ['lab' => true], 'status' => 'queued',
        ]);
        $job = new RunScan($scan->id);
        $ref = new \ReflectionProperty($job, 'scan');
        $ref->setAccessible(true);
        $ref->setValue($job, $scan);

        $this->invokePrivate2($job, 'cover', ['BFLA · autorização por função', '/admin/relatorio', 'falha']);
        $this->invokePrivate2($job, 'cover', ['Acesso sem autenticação', '/painel', 'protegido']);
        $this->invokePrivate2($job, 'cover', ['IDOR · enumeração de ID', '/bookings/{id}', 'nao_testado']);
        $this->invokePrivate2($job, 'saveCoverage', []);

        $rows = $scan->fresh()->coverage;
        $this->assertCount(3, $rows);
        $verdicts = array_column($rows, 'verdict', 'check');
        $this->assertSame('falha', $verdicts['BFLA · autorização por função']);
        $this->assertSame('protegido', $verdicts['Acesso sem autenticação']);
        $this->assertSame('nao_testado', $verdicts['IDOR · enumeração de ID']);
        $this->assertNotSame($verdicts['Acesso sem autenticação'], $verdicts['IDOR · enumeração de ID']);
    }

    public function test_mass_assignment_persists_forbidden_field(): void
    {
        $persisted = ApiOracles::massAssignmentAssess('/bookings/12', 'role', 'EGIDE-MA-0001',
            ['status' => 200], ['status' => 200, 'fields' => [['key' => 'nota', 'value' => 'x'], ['key' => 'role', 'value' => 'EGIDE-MA-0001']]]);
        $this->assertSame('falha', $persisted['verdict']);
        $this->assertSame('critical', $persisted['finding']['severity']);
        $this->assertSame('Mass assignment · atribuição em massa', $persisted['finding']['category']);
        $this->assertSame('role', $persisted['finding']['evidence']['field']);
        $this->assertSame('/bookings/12', $persisted['finding']['evidence']['path']);

        // Our proxy blocked the write (budget/scope) → could not test, NOT "protegido".
        $blocked = ApiOracles::massAssignmentAssess('/bookings/12', 'role', 'EGIDE-MA-0001',
            ['status' => 403, 'blocked' => true], ['status' => 200, 'fields' => [['key' => 'role', 'value' => 'user']]]);
        $this->assertSame('nao_testado', $blocked['verdict']);
        $this->assertNull($blocked['finding']);

        // Field absent / unchanged after the write → server ignored it, protected.
        $ignored = ApiOracles::massAssignmentAssess('/bookings/12', 'role', 'EGIDE-MA-0001',
            ['status' => 200], ['status' => 200, 'fields' => [['key' => 'nota', 'value' => 'x']]]);
        $this->assertSame('protegido', $ignored['verdict']);

        // No readable record after → cannot conclude.
        $noRead = ApiOracles::massAssignmentAssess('/bookings/12', 'role', 'EGIDE-MA-0001', ['status' => 200], ['status' => 500]);
        $this->assertSame('nao_testado', $noRead['verdict']);
    }

    public function test_excessive_data_exposes_hidden_field(): void
    {
        $exposed = $this->invokePrivate('excessiveAssess', ['/servicos/extratos/1',
            [['key' => 'email_contato', 'value' => 'outro@empresa.test'], ['key' => 'fatura', 'value' => '123']],
            'Fatura 123 · Total R$ 50,00']);
        $this->assertSame('falha', $exposed['verdict']);
        $this->assertSame('ExcessiveData · exposição excessiva', $exposed['finding']['category']);
        $this->assertSame('email_contato', $exposed['finding']['evidence']['field']);

        // Sensitive key but its value IS shown on the screen → not hidden, protected.
        $shown = $this->invokePrivate('excessiveAssess', ['/servicos/extratos/1',
            [['key' => 'email_contato', 'value' => 'outro@empresa.test']], 'Contato: outro@empresa.test']);
        $this->assertSame('protegido', $shown['verdict']);

        // Innocuous extra key (not sensitive) not on screen → protected, not a leak.
        $innocuous = $this->invokePrivate('excessiveAssess', ['/servicos/extratos/1',
            [['key' => 'layout', 'value' => 'compacto']], 'Fatura 123']);
        $this->assertSame('protegido', $innocuous['verdict']);
    }

    public function test_injection_reflected_detects_unescaped_marker(): void
    {
        $probe = '"><egideXSS9ab>';
        $reflected = $this->invokePrivate('injectionReflectedAssess', [$probe, '/busca?q=', 'Resultados para "><egideXSS9ab> encontrados', 'text/html; charset=utf-8']);
        $this->assertSame('falha', $reflected['verdict']);
        $this->assertSame('high', $reflected['finding']['severity']);
        $this->assertSame('InjectionCheck · XSS refletido', $reflected['finding']['category']);
        $this->assertTrue($reflected['finding']['evidence']['reflected']);

        $escaped = $this->invokePrivate('injectionReflectedAssess', [$probe, '/busca?q=', 'Resultados para &quot;&gt;&lt;egideXSS9ab&gt; encontrados', 'text/html']);
        $this->assertSame('protegido', $escaped['verdict']);

        $absent = $this->invokePrivate('injectionReflectedAssess', [$probe, '/busca?q=', 'Nada encontrado', 'text/html']);
        $this->assertSame('protegido', $absent['verdict']);

        // Raw reflection in a NON-html response is not browser-executable XSS → not a finding.
        $jsonEcho = $this->invokePrivate('injectionReflectedAssess', [$probe, '/api/busca?q=', '{"q":"\"><egideXSS9ab>"}', 'application/json']);
        $this->assertNotSame('falha', $jsonEcho['verdict']);
    }

    public function test_injection_time_based_sqli(): void
    {
        $slow = $this->invokePrivate('injectionTimeAssess', ['/itens?id=1', 140.0, 5300.0]);
        $this->assertSame('falha', $slow['verdict']);
        $this->assertSame('high', $slow['finding']['severity']);
        $this->assertSame('InjectionCheck · SQLi por tempo', $slow['finding']['category']);

        $fast = $this->invokePrivate('injectionTimeAssess', ['/itens?id=1', 140.0, 190.0, 200]);
        $this->assertSame('protegido', $fast['verdict']);

        $noBaseline = $this->invokePrivate('injectionTimeAssess', ['/itens?id=1', 0.0, 5000.0, 200]);
        $this->assertSame('nao_testado', $noBaseline['verdict']);

        // Payload hit the timeout (status 0, no elapsed) → a hang is the STRONGEST SQLi signal, never "protegido".
        $timedOut = $this->invokePrivate('injectionTimeAssess', ['/itens?id=1', 140.0, 0.0, 0]);
        $this->assertSame('nao_testado', $timedOut['verdict']);
    }

    public function test_ssrf_callback_received_proves_finding(): void
    {
        $hit = $this->invokePrivate('ssrfAssess', ['/webhook', [['source_ip' => '203.0.113.9', 'path' => '/colaborador/tok', 'received_at' => '2026-11-09 10:00:00']], 'tok-abc']);
        $this->assertSame('falha', $hit['verdict']);
        $this->assertSame('high', $hit['finding']['severity']);
        $this->assertSame('SSRF · callback out-of-band', $hit['finding']['category']);
        $this->assertSame('203.0.113.9', $hit['finding']['evidence']['source_ip']);

        // No callback arrived: blind SSRF behind an egress firewall is indistinguishable from safe → nao_testado, never "protegido".
        $none = $this->invokePrivate('ssrfAssess', ['/webhook', [], 'tok-abc']);
        $this->assertSame('nao_testado', $none['verdict']);
        $this->assertNull($none['finding']);
    }

    public function test_jwt_weakness_oracle(): void
    {
        $jwt = fn ($h, $p) => rtrim(strtr(base64_encode(json_encode($h)), '+/', '-_'), '=').'.'.rtrim(strtr(base64_encode(json_encode($p)), '+/', '-_'), '=').'.sig';

        $none = $this->invokePrivate('jwtAssess', [$jwt(['alg' => 'none', 'typ' => 'JWT'], ['sub' => '1'])]);
        $this->assertSame('falha', $none['verdict']);
        $this->assertSame('critical', $none['finding']['severity']);
        $this->assertSame('AuthCheck · JWT fraco', $none['finding']['category']);
        $this->assertSame('none', $none['finding']['evidence']['alg']);

        $noExp = $this->invokePrivate('jwtAssess', [$jwt(['alg' => 'HS256', 'typ' => 'JWT'], ['sub' => '1'])]);
        $this->assertSame('falha', $noExp['verdict']);
        $this->assertSame('high', $noExp['finding']['severity']);
        $this->assertFalse($noExp['finding']['evidence']['has_exp']);

        // Well-formed HS256+exp: black-box cannot prove the signature/secret is strong → nao_testado, not a clean "protegido".
        $wellFormed = $this->invokePrivate('jwtAssess', [$jwt(['alg' => 'HS256', 'typ' => 'JWT'], ['sub' => '1', 'exp' => time() + 3600])]);
        $this->assertSame('nao_testado', $wellFormed['verdict']);

        $notJwt = $this->invokePrivate('jwtAssess', ['sessao-opaca-xyz']);
        $this->assertSame('nao_testado', $notJwt['verdict']);
    }

    public function test_auth_rate_limit_oracle(): void
    {
        $noLimit = $this->invokePrivate('authRateAssess', ['/auth/login', [401, 401, 401, 401, 401, 401, 401, 401, 401, 401]]);
        $this->assertSame('falha', $noLimit['verdict']);
        $this->assertSame('AuthCheck · sem limite de tentativas', $noLimit['finding']['category']);
        $this->assertSame(10, $noLimit['finding']['evidence']['attempts']);

        $throttled = $this->invokePrivate('authRateAssess', ['/auth/login', [401, 401, 401, 429, 429]]);
        $this->assertSame('protegido', $throttled['verdict']);

        $tooFew = $this->invokePrivate('authRateAssess', ['/auth/login', [401, 401]]);
        $this->assertSame('nao_testado', $tooFew['verdict']);
    }

    public function test_inventory_oracle_lists_unlinked_endpoints(): void
    {
        $found = $this->invokePrivate('inventoryAssess', [['/admin/relatorio', '/api/v0/legado', '/faturas'], ['/faturas', '/painel']]);
        $this->assertSame('falha', $found['verdict']);
        $this->assertSame('InventoryCheck · inventário de API', $found['finding']['category']);
        $this->assertContains('/api/v0/legado', $found['finding']['evidence']['endpoints']);
        $this->assertNotContains('/faturas', $found['finding']['evidence']['endpoints']);

        $allLinked = $this->invokePrivate('inventoryAssess', [['/faturas'], ['/faturas', '/painel']]);
        $this->assertSame('protegido', $allLinked['verdict']);
    }
}
