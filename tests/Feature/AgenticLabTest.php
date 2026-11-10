<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\User;
use App\Security\Planner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class AgenticLabTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake();
    }

    private ?FakeRunScan $lastFake = null;

    private function runLoop(bool $vulnerable, bool $escaping = false, int $budget = 1000): Scan
    {
        $user = User::factory()->create();
        $scan = Scan::create([
            'user_id' => $user->id, 'name' => 'Lab agêntico', 'mode' => 'laboratory', 'status' => 'running',
            'scope' => ['lab' => true, 'url' => 'http://lab.egide.test:8788/vulneravel',
                'rules' => [['method' => '*', 'path' => '/', 'prefix' => true]], 'denied' => [], 'api' => null],
            'provider' => 'lab', 'budget' => $budget,
        ]);

        $fake = new FakeRunScan($scan->id);
        $fake->vulnerable = $vulnerable;
        $fake->escaping = $escaping;
        $this->lastFake = $fake;
        $inventory = [
            'GET /servicos/vulneravel/busca' => ['method' => 'GET', 'path' => '/servicos/vulneravel/busca', 'params' => ['q'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'GET /servicos/vulneravel/consulta' => ['method' => 'GET', 'path' => '/servicos/vulneravel/consulta', 'params' => ['id'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'GET /servicos/vulneravel/integrador' => ['method' => 'GET', 'path' => '/servicos/vulneravel/integrador', 'params' => ['url'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'POST /servicos/vulneravel/login' => ['method' => 'POST', 'path' => '/servicos/vulneravel/login', 'params' => [], 'body' => ['email', 'senha'], 'auth' => false, 'seen_in' => 'xhr'],
            'GET /servicos/vulneravel/arquivo' => ['method' => 'GET', 'path' => '/servicos/vulneravel/arquivo', 'params' => ['file'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'POST /servicos/vulneravel/graphql' => ['method' => 'POST', 'path' => '/servicos/vulneravel/graphql', 'params' => [], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'GET /servicos/vulneravel/pedido' => ['method' => 'GET', 'path' => '/servicos/vulneravel/pedido', 'params' => ['id'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'GET /servicos/vulneravel/retorno' => ['method' => 'GET', 'path' => '/servicos/vulneravel/retorno', 'params' => ['destino'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
        ];

        $reflection = new \ReflectionClass(RunScan::class);
        foreach (['scan' => $scan, 'inventory' => $inventory] as $property => $value) {
            $prop = $reflection->getProperty($property);
            $prop->setAccessible(true);
            $prop->setValue($fake, $value);
        }

        $method = $reflection->getMethod('agenticBattery');
        $method->setAccessible(true);
        $method->invoke($fake, new Planner);

        $save = $reflection->getMethod('saveCoverage');
        $save->setAccessible(true);
        $save->invoke($fake);

        return $scan->fresh();
    }

    public function test_findings_carry_a_screenshot_of_the_proof(): void
    {
        Storage::fake();
        $scan = $this->runLoop(vulnerable: true);

        $reflected = $scan->findings()->where('category', 'InjectionCheck · XSS refletido')->first();
        $this->assertTrue($reflected->evidence['screenshot'] ?? false);
        $this->assertTrue(Storage::exists('findings/'.$reflected->id.'.jpg'));
        $this->assertNotEmpty(array_filter($this->lastFake->gotos, fn ($url) => str_starts_with($url, '/servicos/vulneravel/busca?q=')));

        $dom = $scan->findings()->where('category', 'InjectionCheck · DOM XSS')->first();
        $this->assertTrue($dom->evidence['screenshot'] ?? false);

        $redirect = $scan->findings()->where('category', 'RedirectCheck · open redirect')->first();
        $this->assertArrayNotHasKey('screenshot', $redirect->evidence);
        $this->assertSame([], array_filter($this->lastFake->gotos, fn ($url) => str_contains($url, 'retorno')));
    }

    public function test_dom_sweep_runs_before_the_endpoint_battery(): void
    {
        $checks = array_column((array) $this->runLoop(vulnerable: true)->coverage, 'check');

        $this->assertLessThan(array_search('InjectionCheck · XSS refletido', $checks), array_search('InjectionCheck · DOM XSS', $checks));
    }

    public function test_live_view_is_refreshed_periodically_during_the_battery(): void
    {
        $this->invokeWith([], 'agenticBattery', 1000);
        $frames = $this->lastFake->frames;

        $this->assertContains(true, $frames);
        $this->assertLessThan(count($frames) / 2, count(array_filter($frames)), 'captura periódica, não a cada sonda');
    }

    public function test_agentic_loop_finds_planted_vulnerabilities_with_proof(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $categories = $scan->findings()->pluck('category')->all();

        $this->assertContains('InjectionCheck · XSS refletido', $categories);
        $this->assertContains('InjectionCheck · SQLi por tempo', $categories);
        $this->assertContains('SSRF · callback out-of-band', $categories);
    }

    public function test_agentic_loop_reports_no_false_positive_on_fixed_variant(): void
    {
        $scan = $this->runLoop(vulnerable: false);
        $this->assertSame(0, $scan->findings()->count());
    }

    public function test_agentic_loop_does_not_flag_escaped_reflection(): void
    {
        $scan = $this->runLoop(vulnerable: true, escaping: true);
        $this->assertNotContains('InjectionCheck · XSS refletido', $scan->findings()->pluck('category')->all());
    }

    public function test_get_probes_never_assert_login_rate_limit(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $this->assertNotContains('AuthCheck · sem limite de tentativas', $scan->findings()->pluck('category')->all());
    }

    public function test_agentic_loop_finds_wave2_vulnerabilities(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $categories = $scan->findings()->pluck('category')->all();
        $this->assertContains('InjectionCheck · SQLi por erro', $categories);
        $this->assertContains('InjectionCheck · path traversal', $categories);
        $this->assertContains('InventoryCheck · GraphQL introspection', $categories);
    }

    public function test_agentic_loop_finds_dom_xss_and_nosql(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $categories = $scan->findings()->pluck('category')->all();
        $this->assertContains('InjectionCheck · DOM XSS', $categories);
        $this->assertContains('InjectionCheck · NoSQL', $categories);
    }

    public function test_agentic_loop_finds_boolean_sqli_and_open_redirect(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $findings = $scan->findings()->get();
        $categories = $findings->pluck('category')->all();

        $this->assertContains('InjectionCheck · SQLi booleano', $categories);
        $this->assertContains('RedirectCheck · open redirect', $categories);
        $this->assertSame(1, $findings->where('category', 'InjectionCheck · SQLi booleano')->count(), 'um achado por ponto, não um por payload');
        $this->assertSame(1, $findings->where('category', 'RedirectCheck · open redirect')->count(), 'um achado por ponto, não um por payload');
    }

    public function test_fixed_variant_marks_boolean_sqli_and_redirect_as_protected(): void
    {
        $rows = collect((array) $this->runLoop(vulnerable: false)->coverage);
        $verdicts = fn (string $check, string $route) => $rows->where('check', $check)->where('route', $route)->pluck('verdict')->unique()->values()->all();

        $this->assertSame(['protegido'], $verdicts('InjectionCheck · SQLi booleano', '/servicos/vulneravel/pedido'));
        $this->assertSame(['protegido'], $verdicts('RedirectCheck · open redirect', '/servicos/vulneravel/retorno'));
    }

    public function test_a_confirmed_point_yields_one_finding_not_one_per_payload(): void
    {
        $findings = $this->runLoop(vulnerable: true)->findings()->get();

        foreach (['InjectionCheck · SQLi por tempo', 'InjectionCheck · SQLi por erro', 'InjectionCheck · NoSQL', 'InjectionCheck · path traversal'] as $category) {
            $this->assertSame(1, $findings->where('category', $category)->count(), $category);
        }
    }

    public function test_boolean_sqli_is_not_repeated_on_a_parameter_already_proven_injectable(): void
    {
        $rows = collect((array) $this->runLoop(vulnerable: true)->coverage);

        $this->assertTrue($rows->contains(fn ($row) => $row['check'] === 'InjectionCheck · SQLi por tempo' && $row['route'] === '/servicos/vulneravel/consulta' && $row['verdict'] === 'falha'));
        $this->assertFalse($rows->contains(fn ($row) => $row['check'] === 'InjectionCheck · SQLi booleano' && $row['route'] === '/servicos/vulneravel/consulta'));
    }

    public function test_agentic_phase_leaves_room_for_the_configuration_sweep(): void
    {
        $scan = $this->runLoop(vulnerable: true, budget: 60);

        $this->assertGreaterThan(0, $scan->request_count);
        $this->assertLessThanOrEqual(60 - 14, $scan->request_count, 'a varredura de configuração usa até 14 sondas');
        $this->assertTrue($scan->events()->where('title', 'Orçamento reservado para a verificação de configuração')->exists());
    }

    private function invokeWith(array $state, string $method, int $budget, bool $vulnerable = true, int $navigationCost = 1): Scan
    {
        $scan = Scan::create([
            'user_id' => User::factory()->create()->id, 'name' => 'Lab parcial', 'mode' => 'laboratory', 'status' => 'running',
            'scope' => ['lab' => true, 'url' => 'http://lab.egide.test:8788/vulneravel',
                'rules' => [['method' => '*', 'path' => '/', 'prefix' => true]], 'denied' => [], 'api' => null],
            'provider' => 'lab', 'budget' => $budget,
        ]);
        $fake = new FakeRunScan($scan->id);
        $fake->vulnerable = $vulnerable;
        $fake->navigationCost = $navigationCost;
        $this->lastFake = $fake;
        $reflection = new \ReflectionClass(RunScan::class);
        $inventory = ['GET /servicos/vulneravel/busca' => ['method' => 'GET', 'path' => '/servicos/vulneravel/busca', 'params' => ['q'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr']];
        foreach (['scan' => $scan, 'inventory' => $inventory, ...$state] as $property => $value) {
            $prop = $reflection->getProperty($property);
            $prop->setAccessible(true);
            $prop->setValue($fake, $value);
        }
        $call = $reflection->getMethod($method);
        $call->setAccessible(true);
        $call->invoke($fake, ...($method === 'agenticBattery' ? [new Planner] : []));

        return $scan->fresh();
    }

    public function test_agentic_phase_stops_in_time_for_the_configuration_sweep(): void
    {
        $scan = $this->invokeWith(['startedAt' => microtime(true) - (config('egide.session_minutes') * 60 - 100)], 'agenticBattery', 1000);

        $this->assertSame(0, (int) $scan->request_count, 'a varredura de configuração precisa terminar antes do teto do job');
        $this->assertTrue($scan->events()->where('title', 'Orçamento reservado para a verificação de configuração')->exists());
    }

    public function test_a_seven_minute_old_session_still_runs_active_checks(): void
    {
        $scan = $this->invokeWith(['startedAt' => microtime(true) - 430], 'agenticBattery', 1000);

        $this->assertGreaterThan(0, (int) $scan->request_count);
    }

    public function test_dom_navigations_that_load_subresources_still_respect_the_reserve(): void
    {
        $scan = $this->invokeWith(['allowed' => 70], 'domXssSweep', 100, vulnerable: false, navigationCost: 8);

        $this->assertLessThanOrEqual(100 - 14, $scan->request_count, 'a varredura de configuração usa até 14 sondas');
    }

    public function test_dom_sweep_stops_after_the_first_confirmed_execution(): void
    {
        $rows = collect((array) $this->runLoop(vulnerable: true)->coverage)->where('check', 'InjectionCheck · DOM XSS');

        $this->assertCount(1, $rows);
        $this->assertSame('falha', $rows->first()['verdict']);
    }

    public function test_dom_sweep_only_probes_query_sources_the_bundle_reads(): void
    {
        $rows = collect((array) $this->runLoop(vulnerable: false)->coverage)->where('check', 'InjectionCheck · DOM XSS');

        $this->assertNotEmpty($rows);
        $this->assertFalse($rows->contains(fn ($row) => str_contains($row['route'], '?')));
    }

    public function test_clientscan_static_coverage_never_claims_falha(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $static = array_values(array_filter((array) $scan->coverage, fn ($c) => $c['check'] === 'ClientScan · sinks DOM'));
        $this->assertNotEmpty($static);
        $this->assertNotSame('falha', $static[0]['verdict']);
    }
}
