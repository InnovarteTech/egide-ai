<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class EgideBenchTest extends TestCase
{
    use RefreshDatabase;

    private const BFLA = 'BFLA · autorização por função';

    private const SQLI = 'InjectionCheck · SQLi por tempo';

    private const XSS = 'InjectionCheck · XSS refletido';

    private const SSRF = 'SSRF · callback out-of-band';

    private const BOLA = 'BOLA · autorização por objeto';

    private const COOKIES = 'Configuração · cookies';

    private ?User $owner = null;

    private function labSession(string $mode, array $coverage = [], array $findings = [], array $attributes = []): Scan
    {
        $this->owner ??= User::factory()->create();
        $variant = $mode === 'retest' ? 'corrigido' : 'vulneravel';
        $scan = Scan::create(array_merge([
            'user_id' => $this->owner->id, 'name' => 'Laboratório', 'mode' => $mode, 'status' => 'completed', 'provider' => 'anthropic',
            'scope' => ['lab' => true, 'url' => "http://lab.egide.test:8788/{$variant}"],
            'coverage' => $coverage, 'request_count' => 100, 'result' => $mode === 'retest' ? 'protected' : 'exposure',
            'started_at' => now()->subMinutes(10), 'finished_at' => now(),
        ], $attributes));
        foreach ($findings as $finding) {
            $scan->findings()->create(array_merge([
                'title' => 'Achado sintético', 'severity' => 'high', 'evidence' => ['path' => '/x'], 'remediation' => 'Corrija.',
            ], is_string($finding) ? ['category' => $finding] : $finding));
        }

        return $scan;
    }

    private function cover(string $check, string $verdict, string $route = '/rota'): array
    {
        return ['check' => $check, 'route' => $route, 'verdict' => $verdict];
    }

    private function bench(array $options = []): array
    {
        $this->assertSame(0, Artisan::call('egide:bench', ['--json' => true, ...$options]));

        return json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);
    }

    private function classes(array $report): array
    {
        return collect($report['originais']['classes'])->keyBy('classe')->all();
    }

    public function test_detection_rate_pass_at_k_and_union_over_original_sessions(): void
    {
        $this->labSession('laboratory', [
            $this->cover(self::BFLA, 'protegido', '/a'), $this->cover(self::BFLA, 'falha', '/b'),
            $this->cover(self::SQLI, 'protegido'), $this->cover(self::XSS, 'nao_testado'),
        ], [self::BFLA, self::COOKIES, ['category' => self::SQLI, 'track' => 'observacao']]);
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'protegido'), $this->cover(self::SQLI, 'falha')], [self::SQLI]);
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'falha'), $this->cover(self::SQLI, 'protegido'), $this->cover(self::SSRF, 'protegido')]);

        $this->labSession('external', [$this->cover(self::SSRF, 'falha')], [self::SSRF], ['scope' => ['url' => 'https://app.exemplo.com']]);
        $this->labSession('laboratory', [$this->cover(self::SSRF, 'falha')], [self::SSRF], ['status' => 'failed']);
        $this->labSession('laboratory', [$this->cover(self::XSS, 'falha')], [self::XSS], ['status' => 'running', 'finished_at' => null]);
        $this->labSession('retest', [$this->cover(self::XSS, 'falha')]);

        $report = $this->bench();
        $originais = $report['originais'];
        $classes = $this->classes($report);

        $this->assertSame(3, $originais['sessoes']);
        $this->assertSame(3, $originais['k']);
        $this->assertSame([self::BFLA, self::SQLI, self::COOKIES, self::SSRF, self::XSS], collect($originais['classes'])->pluck('classe')->all());

        $this->assertSame(2, $classes[self::BFLA]['sessoes_com_falha']);
        $this->assertSame(3, $classes[self::BFLA]['sessoes_testadas']);
        $this->assertEqualsWithDelta(2 / 3, $classes[self::BFLA]['taxa_deteccao'], 0.0001);
        $this->assertTrue($classes[self::BFLA]['pass_at_k']);

        $this->assertSame(1, $classes[self::SQLI]['sessoes_com_falha']);
        $this->assertEqualsWithDelta(1 / 3, $classes[self::SQLI]['taxa_deteccao'], 0.0001);
        $this->assertTrue($classes[self::SQLI]['pass_at_k']);

        $this->assertSame(1, $classes[self::COOKIES]['sessoes_com_falha']);
        $this->assertSame(1, $classes[self::COOKIES]['sessoes_testadas']);

        $this->assertSame(0, $classes[self::SSRF]['sessoes_com_falha']);
        $this->assertSame(1, $classes[self::SSRF]['sessoes_testadas']);
        $this->assertFalse($classes[self::SSRF]['pass_at_k']);

        $this->assertSame(0, $classes[self::XSS]['sessoes_testadas']);
        $this->assertEquals(0, $classes[self::XSS]['taxa_deteccao']);
        $this->assertFalse($classes[self::XSS]['pass_at_k']);

        $this->assertSame([self::BFLA, self::SQLI, self::COOKIES], $originais['uniao']);
        $this->assertEqualsWithDelta(0.6, $originais['cobertura_uniao'], 0.0001);
        $this->assertEqualsWithDelta(4 / 15, $originais['pass_at_1'], 0.0001);
        $this->assertEqualsWithDelta(1.0, $originais['achados_por_sessao'], 0.0001);
    }

    public function test_finding_categories_count_as_detected_classes_in_original_sessions(): void
    {
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'protegido')], [self::BOLA, ['category' => self::SSRF, 'track' => 'observacao']]);
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'protegido')], [self::BOLA]);
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'falha')]);
        $this->labSession('retest', [], [self::XSS]);

        $report = $this->bench();
        $originais = $report['originais'];
        $classes = $this->classes($report);

        $this->assertSame([self::BOLA, self::BFLA], array_keys($classes));
        $this->assertSame(2, $classes[self::BOLA]['sessoes_com_falha']);
        $this->assertSame(2, $classes[self::BOLA]['sessoes_testadas']);
        $this->assertEqualsWithDelta(2 / 3, $classes[self::BOLA]['taxa_deteccao'], 0.0001);
        $this->assertTrue($classes[self::BOLA]['pass_at_k']);
        $this->assertSame(1, $classes[self::BFLA]['sessoes_com_falha']);
        $this->assertSame([self::BOLA, self::BFLA], $originais['uniao']);
        $this->assertEqualsWithDelta(1.0, $originais['cobertura_uniao'], 0.0001);
        $this->assertEqualsWithDelta(0.5, $originais['pass_at_1'], 0.0001);
        $this->assertSame([], collect($report['sessoes'])->firstWhere('variante', 'corrigido')['classes']);
    }

    public function test_retest_false_positives_ignore_configuration_categories(): void
    {
        $this->labSession('retest', [$this->cover(self::BFLA, 'falha')], [
            'Configuração · cabeçalhos HTTP', 'Configuração · cookies', 'InventoryCheck · inventário de API',
            self::BFLA, ['category' => self::SQLI, 'track' => 'observacao'],
        ]);
        $this->labSession('retest', [], ['Configuração · cabeçalhos HTTP']);
        $this->labSession('retest', [], [self::BFLA, self::SSRF, self::SSRF]);
        $this->labSession('laboratory', [], [self::SQLI]);

        $retestes = $this->bench()['retestes'];

        $this->assertSame(3, $retestes['sessoes']);
        $this->assertSame(4, $retestes['falsos_positivos']);
        $this->assertEqualsWithDelta(4 / 3, $retestes['fp_por_sessao'], 0.0001);
        $this->assertSame(2, $retestes['sessoes_com_fp']);
        $this->assertEqualsWithDelta(2 / 3, $retestes['taxa_sessoes_com_fp'], 0.0001);
        $this->assertSame([self::BFLA => 2, self::SSRF => 2], $retestes['categorias_fp']);
    }

    public function test_configuration_categories_cover_headers_cookies_version_and_inventory(): void
    {
        $categories = $this->bench()['parametros']['categorias_configuracao'];

        $this->assertSame(['Configuração · cabeçalhos HTTP', 'Configuração · cookies', 'InventoryCheck · inventário de API'], $categories);
    }

    public function test_cost_per_session_per_finding_and_tokens_from_the_budget_event(): void
    {
        $this->freezeTime();
        $first = $this->labSession('laboratory', [], [self::BFLA, self::SQLI], [
            'request_count' => 120, 'started_at' => now()->subSeconds(600), 'finished_at' => now(),
        ]);
        $first->event('system', 'Orçamento por fase', null, ['fases' => ['caca' => ['spent' => 40]], 'tokens' => ['input' => 1000, 'output' => 500]]);
        $this->labSession('laboratory', [], [self::SSRF], [
            'request_count' => 80, 'summary' => ['requests' => 90, 'risk' => 'high'], 'started_at' => now()->subSeconds(300), 'finished_at' => now(),
        ]);
        $retest = $this->labSession('retest', [], [], ['request_count' => 60, 'started_at' => now()->subSeconds(200), 'finished_at' => now()]);
        $retest->event('system', 'Orçamento por fase', null, ['tokens' => 700]);

        $report = $this->bench();
        $custo = $report['custo'];

        $this->assertEqualsWithDelta(105, $custo['originais']['requisicoes_media'], 0.0001);
        $this->assertEqualsWithDelta(450, $custo['originais']['duracao_media_s'], 0.0001);
        $this->assertEqualsWithDelta(70, $custo['originais']['requisicoes_por_achado'], 0.0001);
        $this->assertEqualsWithDelta(1500, $custo['originais']['tokens_media'], 0.0001);
        $this->assertSame(1, $custo['originais']['sessoes_com_tokens']);

        $this->assertEqualsWithDelta(60, $custo['retestes']['requisicoes_media'], 0.0001);
        $this->assertEqualsWithDelta(200, $custo['retestes']['duracao_media_s'], 0.0001);
        $this->assertNull($custo['retestes']['requisicoes_por_achado']);
        $this->assertEqualsWithDelta(700, $custo['retestes']['tokens_media'], 0.0001);

        $rows = collect($report['sessoes'])->keyBy('id');
        $this->assertSame(120, $rows[$first->id]['requisicoes']);
        $this->assertSame(600, $rows[$first->id]['duracao_s']);
        $this->assertSame(1500, $rows[$first->id]['tokens']);
        $this->assertSame('vulneravel', $rows[$first->id]['variante']);
        $this->assertSame('corrigido', $rows[$retest->id]['variante']);
    }

    public function test_cost_without_budget_event_reports_no_tokens(): void
    {
        $this->labSession('laboratory', [], [self::BFLA], ['started_at' => null]);

        $custo = $this->bench()['custo']['originais'];

        $this->assertNull($custo['tokens_media']);
        $this->assertSame(0, $custo['sessoes_com_tokens']);
        $this->assertNull($custo['duracao_media_s']);
        $this->assertEqualsWithDelta(100, $custo['requisicoes_por_achado'], 0.0001);
    }

    public function test_malformed_coverage_and_budget_data_are_ignored(): void
    {
        $scan = $this->labSession('laboratory', [
            'texto solto', ['route' => '/sem-classe', 'verdict' => 'falha'], ['check' => self::BFLA, 'verdict' => ['falha']],
            ['check' => self::SQLI, 'verdict' => 'desconhecido'], $this->cover(self::SQLI, 'falha'),
        ]);
        $scan->event('system', 'Orçamento por fase', null, ['tokens' => ['detalhe' => 'indisponível']]);

        $report = $this->bench();
        $classes = $this->classes($report);

        $this->assertSame([self::SQLI, self::BFLA], array_keys($classes));
        $this->assertSame(0, $classes[self::BFLA]['sessoes_testadas']);
        $this->assertSame(1, $classes[self::SQLI]['sessoes_com_falha']);
        $this->assertNull($report['sessoes'][0]['tokens']);
    }

    public function test_last_option_keeps_the_most_recent_sessions_of_each_variant(): void
    {
        $this->labSession('laboratory', [$this->cover(self::SSRF, 'falha')], [], ['created_at' => now()->subDays(3)]);
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'falha')], [], ['created_at' => now()->subDays(2)]);
        $this->labSession('laboratory', [$this->cover(self::SQLI, 'falha')], [], ['created_at' => now()->subDay()]);
        $this->labSession('retest', [], [self::BFLA], ['created_at' => now()->subDays(3)]);
        $this->labSession('retest', [], [], ['created_at' => now()->subDays(2)]);
        $this->labSession('retest', [], [], ['created_at' => now()->subDay()]);

        $report = $this->bench(['--last' => 2]);

        $this->assertSame(2, $report['originais']['k']);
        $this->assertSame([self::BFLA, self::SQLI], $report['originais']['uniao']);
        $this->assertSame(2, $report['retestes']['sessoes']);
        $this->assertSame(0, $report['retestes']['falsos_positivos']);
        $this->assertSame(2, $report['parametros']['last']);
    }

    public function test_table_output_is_readable_in_portuguese(): void
    {
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'falha'), $this->cover(self::SQLI, 'protegido')], [self::BFLA]);
        $this->labSession('retest', [], [self::SSRF, 'Configuração · cookies']);
        $this->labSession('retest', [], ['Configuração · cookies']);

        $this->artisan('egide:bench')
            ->expectsOutputToContain('Originais (variante vulnerável)')
            ->expectsOutputToContain('Taxa de detecção')
            ->expectsOutputToContain('100,0%')
            ->expectsOutputToContain('Cobertura por união')
            ->expectsOutputToContain('Retestes (variante corrigida)')
            ->expectsOutputToContain('Falsos positivos: 1 (0,5 por sessão) · Sessões com falso positivo: 1 de 2 (50,0%)')
            ->expectsOutputToContain('Custo')
            ->assertSuccessful();
    }

    public function test_without_sessions_prints_a_clear_message(): void
    {
        $this->labSession('external', [$this->cover(self::SSRF, 'falha')], [], ['scope' => ['url' => 'https://app.exemplo.com']]);

        $this->artisan('egide:bench')
            ->expectsOutputToContain('Nenhuma sessão de laboratório concluída encontrada')
            ->assertSuccessful();

        $report = $this->bench();
        $this->assertSame('Nenhuma sessão de laboratório concluída encontrada.', $report['mensagem']);
        $this->assertSame(0, $report['originais']['sessoes']);
        $this->assertNull($report['originais']['cobertura_uniao']);
        $this->assertSame(0, $report['retestes']['sessoes']);
        $this->assertNull($report['retestes']['fp_por_sessao']);
        $this->assertSame([], $report['sessoes']);
    }

    public function test_invalid_last_option_is_rejected(): void
    {
        $this->artisan('egide:bench', ['--last' => '0'])
            ->expectsOutputToContain('--last')
            ->assertFailed();
    }

    public function test_session_option_limits_the_report_to_the_given_sessions(): void
    {
        $chosen = $this->labSession('laboratory', [$this->cover(self::BFLA, 'falha')]);
        $this->labSession('laboratory', [$this->cover(self::SQLI, 'falha')]);
        $retest = $this->labSession('retest');
        $this->labSession('retest', [], [self::SSRF]);

        $report = $this->bench(['--sessao' => [$chosen->id, $retest->id]]);

        $this->assertSame([self::BFLA], $report['originais']['uniao']);
        $this->assertSame(0, $report['retestes']['falsos_positivos']);
        $this->assertEqualsCanonicalizing([$chosen->id, $retest->id], array_column($report['sessoes'], 'id'));
    }

    public function test_gabarito_compares_detection_against_planted_failures(): void
    {
        $fixture = tempnam(sys_get_temp_dir(), 'gabarito').'.json';
        file_put_contents($fixture, json_encode(['classes' => [self::BFLA, self::SQLI, self::SSRF, 'Inexistente']]));
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'falha'), $this->cover(self::SQLI, 'protegido')], [self::BFLA]);

        $report = $this->bench(['--gabarito' => $fixture]);
        $gabarito = $report['gabarito'];

        $this->assertSame(4, $gabarito['esperadas']);
        $this->assertSame(1, $gabarito['detectadas']);
        $this->assertEqualsWithDelta(0.25, $gabarito['cobertura'], 0.0001);
        $this->assertSame(['Inexistente', self::SQLI, self::SSRF], $gabarito['faltantes']);
        $this->assertSame(['Inexistente', self::SSRF], $gabarito['nunca_testadas']);
        unlink($fixture);
    }

    public function test_gabarito_min_fails_below_the_threshold(): void
    {
        $fixture = tempnam(sys_get_temp_dir(), 'gabarito').'.json';
        file_put_contents($fixture, json_encode(['classes' => [self::BFLA, self::SQLI]]));
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'falha')]);

        $this->artisan('egide:bench', ['--gabarito' => $fixture, '--min' => '0.5'])->assertSuccessful();
        $this->artisan('egide:bench', ['--gabarito' => $fixture, '--min' => '0.6'])
            ->expectsOutputToContain('abaixo do mínimo')
            ->assertFailed();
        $this->artisan('egide:bench', ['--gabarito' => $fixture, '--min' => 'abc'])
            ->expectsOutputToContain('--min')
            ->assertFailed();
        unlink($fixture);
    }

    public function test_gabarito_missing_or_empty_file_is_ignored(): void
    {
        $this->labSession('laboratory', [$this->cover(self::BFLA, 'falha')]);

        $report = $this->bench(['--gabarito' => 'nao-existe.json']);
        $this->assertArrayNotHasKey('gabarito', $report);
    }

    public function test_run_queues_lab_and_retest_pairs_with_the_lab_scope(): void
    {
        Queue::fake();
        $admin = User::factory()->create(['is_admin' => true]);

        $this->artisan('egide:bench:run', ['--pares' => 2, '--orcamento' => 250, '--espera' => 1, '--intervalo' => 1])
            ->expectsOutputToContain('4 sessões enfileiradas (lab)')
            ->expectsOutputToContain('Tempo esgotado')
            ->assertFailed();

        $scans = Scan::orderBy('id')->get();
        $this->assertSame(['laboratory', 'retest', 'laboratory', 'retest'], $scans->pluck('mode')->all());
        $this->assertTrue($scans->every(fn (Scan $scan) => $scan->user_id === $admin->id && $scan->provider === 'lab' && $scan->budget === 250));
        $this->assertSame('http://lab.egide.test:8788/vulneravel', $scans[0]->scope['url']);
        $this->assertSame('http://lab.egide.test:8788/corrigido', $scans[1]->scope['url']);
        $this->assertTrue($scans[1]->scope['lab']);
        Queue::assertPushed(RunScan::class, 4);
    }

    public function test_run_requires_an_owner_and_the_ai_engine_when_asked(): void
    {
        Queue::fake();
        $this->artisan('egide:bench:run')->expectsOutputToContain('Nenhum administrador')->assertFailed();

        User::factory()->create(['is_admin' => true]);
        $this->artisan('egide:bench:run', ['--agente' => true])->expectsOutputToContain('motor de IA')->assertFailed();
        $this->artisan('egide:bench:run', ['--pares' => '0'])->expectsOutputToContain('--pares')->assertFailed();

        $this->assertSame(0, Scan::count());
        Queue::assertNothingPushed();
    }
}
