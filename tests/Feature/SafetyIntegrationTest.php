<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Hypothesis;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Security\BudgetLedger;
use App\Security\Planner;
use App\Security\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use RuntimeException;
use Tests\TestCase;

class SafetyIntegrationTest extends TestCase
{
    use RefreshDatabase;

    private const FOCUS = 'Priorize o módulo de faturas.';

    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake();
    }

    private function labScan(int $budget = 600): Scan
    {
        return Scan::create([
            'user_id' => User::factory()->create()->id, 'name' => 'Laboratório', 'mode' => 'laboratory', 'status' => 'queued',
            'scope' => ['lab' => true, 'url' => 'http://lab.egide.test:8788/vulneravel',
                'rules' => [['method' => '*', 'path' => '/', 'prefix' => true]], 'denied' => [], 'api' => null],
            'provider' => 'lab', 'budget' => $budget,
        ]);
    }

    private function externalScan(): Scan
    {
        $this->app['env'] = 'local';
        config(['egide.local_targets' => true]);
        $target = Target::create([
            'user_id' => User::factory()->create()->id, 'name' => 'Homologação', 'origin' => 'https://app.local.egide.test',
            'entry_path' => '/', 'verification_token' => str_repeat('a', 48), 'local_port' => 8099, 'verified_at' => now(),
            'environment_type' => 'production', 'rules' => [['method' => 'GET', 'path' => '/', 'prefix' => true]], 'denied' => [],
            'credentials' => ['a' => ['email' => 'a@empresa.test', 'password' => 'senha-de-teste', 'marker' => 'EGIDE-0123456789ABCDEF', 'path' => null]],
        ]);
        $target->mergeCasts(['surface' => 'array', 'surface_meta' => 'array'])->forceFill([
            'surface' => [
                ['method' => 'GET', 'path' => '/api/pedidos', 'host' => null, 'params' => ['page'], 'body' => [], 'auth' => true, 'source' => 'openapi'],
                ['method' => 'POST', 'path' => '/api/pedidos', 'host' => null, 'params' => [], 'body' => ['item'], 'auth' => true, 'source' => 'openapi'],
            ],
            'surface_meta' => ['format' => 'openapi', 'count' => 2, 'name' => 'api.json'],
        ])->save();

        return Scan::create([
            'user_id' => $target->user_id, 'target_id' => $target->id, 'name' => $target->name, 'mode' => 'external', 'status' => 'queued',
            'scope' => [...Scope::launch($target), 'retest_of' => null, 'focus' => self::FOCUS], 'credentials' => $target->credentials,
            'provider' => 'anthropic', 'model' => 'claude-teste', 'engine_key' => 'chave-de-teste', 'budget' => 180,
        ]);
    }

    private function fakeAnthropic(): void
    {
        Http::fake(['api.anthropic.com/*' => function ($request) {
            $text = str_contains($request['system'], 'resumo executivo')
                ? json_encode(['risk' => 'low', 'summary' => 'Mapeamento concluído sem achados.', 'priorities' => []])
                : json_encode(['action' => 'finish', 'control' => 0, 'label' => 'Encerrar']);

            return Http::response(['stop_reason' => 'end_turn', 'content' => [['type' => 'text', 'text' => $text]],
                'usage' => ['input_tokens' => 100, 'output_tokens' => 20]]);
        }]);
    }

    private function executeJob(RunScan $job, ?Planner $planner = null): void
    {
        $execute = new \ReflectionMethod(RunScan::class, 'execute');
        $execute->setAccessible(true);
        $execute->invoke($job, $planner ?? new Planner);
    }

    private function prepare(RunScan $job, array $properties): void
    {
        foreach ($properties as $name => $value) {
            $property = new \ReflectionProperty(RunScan::class, $name);
            $property->setAccessible(true);
            $property->setValue($job, $value);
        }
    }

    private function invokeJob(RunScan $job, string $method, array $arguments = []): mixed
    {
        $reflection = new \ReflectionMethod($job, $method);
        $reflection->setAccessible(true);

        return $reflection->invoke($job, ...$arguments);
    }

    public function test_proxy_halt_ends_the_session_cleanly_with_an_error_event(): void
    {
        $scan = $this->labScan();
        $job = new FakeRunScan($scan->id);
        $job->halt = ['reason' => 'Taxa de erros 5xx alta no alvo', 'at' => 1763100000];

        $this->executeJob($job);

        $scan->refresh();
        $this->assertSame('failed', $scan->status);
        $this->assertSame('Sessão pausada pelo proxy: Taxa de erros 5xx alta no alvo', $scan->error);
        $halt = $scan->events()->where('title', 'Parada automática do proxy')->sole();
        $this->assertSame('error', $halt->type);
        $this->assertStringContainsString('Taxa de erros 5xx alta no alvo', $halt->detail);
        $this->assertSame(['reason' => 'Taxa de erros 5xx alta no alvo', 'at' => 1763100000], $halt->data);
        $this->assertSame(['/start', '/observe', '/stop'], array_column($job->calls, 0));
        $this->assertNull($scan->engine_key);
    }

    public function test_soft_checks_do_not_swallow_a_proxy_halt(): void
    {
        $scan = $this->labScan();
        $job = new FakeRunScan($scan->id);
        $job->halt = ['reason' => 'Bloqueio de WAF detectado', 'at' => 1];
        $this->prepare($job, ['scan' => $scan]);

        try {
            $this->invokeJob($job, 'softCheck', ['Sonda de teste', fn () => $this->invokeJob($job, 'observe')]);
            $this->fail('A parada do proxy deveria interromper a sessão.');
        } catch (RuntimeException $error) {
            $this->assertSame('Sessão pausada pelo proxy: Bloqueio de WAF detectado', $error->getMessage());
        }

        $job->halt = null;
        $this->expectExceptionMessage('Sessão pausada pelo proxy: Bloqueio de WAF detectado');
        try {
            $this->invokeJob($job, 'checkStop');
        } finally {
            $this->assertFalse($scan->events()->where('title', 'Verificação não concluída')->exists());
            $this->assertSame(1, $scan->events()->where('title', 'Parada automática do proxy')->count());
        }
    }

    public function test_the_halting_observation_still_records_the_traffic_that_reached_the_target(): void
    {
        $scan = $this->labScan();
        $job = new FakeRunScan($scan->id);
        $this->prepare($job, ['scan' => $scan]);
        foreach (['/servicos/vulneravel/busca', '/servicos/vulneravel/consulta'] as $route) {
            $this->invokeJob($job, 'runner', ['/probe', ['path' => $route]]);
        }
        $job->halt = ['reason' => 'Taxa de erros 5xx alta no alvo', 'at' => 1];

        try {
            $this->invokeJob($job, 'observe', [false]);
            $this->fail('A parada do proxy deveria interromper a sessão.');
        } catch (RuntimeException) {
        }

        $this->assertSame(2, $scan->fresh()->request_count);
        $this->assertSame(2, $scan->events()->where('type', 'network')->count());
        $this->expectExceptionMessage('Sessão pausada pelo proxy');
        $this->invokeJob($job, 'runner', ['/action', ['kind' => 'click', 'control' => 1]]);
    }

    public function test_no_runner_command_leaves_after_a_halt_except_stop(): void
    {
        Http::fake();
        $scan = $this->labScan();
        $job = new RunScan($scan->id);
        $this->prepare($job, ['scan' => $scan, 'halted' => 'Latência alta no alvo']);

        foreach (['/action', '/write', '/probe', '/observe'] as $path) {
            try {
                $this->invokeJob($job, 'runner', [$path, []]);
                $this->fail("{$path} não deveria sair depois da parada.");
            } catch (RuntimeException $error) {
                $this->assertSame('Sessão pausada pelo proxy: Latência alta no alvo', $error->getMessage());
            }
        }

        Http::assertNothingSent();
    }

    public function test_surface_summary_counts_each_tested_route_once(): void
    {
        $job = new RunScan('x');
        $this->prepare($job, [
            'inventory' => [
                'GET /busca' => ['method' => 'GET', 'path' => '/busca', 'seen_in' => 'xhr'],
                'GET /api/pedidos' => ['method' => 'GET', 'path' => '/api/pedidos', 'seen_in' => 'import', 'source' => 'openapi'],
            ],
            'coverage' => [
                ['check' => 'InjectionCheck · DOM XSS', 'route' => '/busca?q', 'verdict' => 'protegido'],
                ['check' => 'InjectionCheck · DOM XSS', 'route' => '/busca#', 'verdict' => 'protegido'],
                ['check' => 'InjectionCheck · XSS refletido', 'route' => '/busca', 'verdict' => 'protegido'],
                ['check' => 'AuthCheck · JWT fraco', 'route' => '(token de sessão)', 'verdict' => 'protegido'],
            ],
        ]);

        $this->assertSame(['vistas' => 2, 'testadas' => 1, 'por_origem' => ['openapi' => 1, 'xhr' => 1]], $this->invokeJob($job, 'surfaceSummary'));
    }

    public function test_phase_budget_keeps_the_minimum_of_phases_not_started_and_tracks_spending(): void
    {
        $scan = $this->labScan(122);
        $job = new FakeRunScan($scan->id);
        $ledger = new BudgetLedger(122, 22, ['observacao' => 0.15, 'prova_cruzada' => 0.15, 'probers' => 0.30, 'caca' => 0.40], BudgetLedger::GUARANTEED);
        $this->prepare($job, ['scan' => $scan, 'ledger' => $ledger]);

        $this->invokeJob($job, 'beginPhase', ['probers']);
        $this->assertTrue($this->invokeJob($job, 'budgetAllows', [30]));
        $this->assertFalse($this->invokeJob($job, 'budgetAllows', [31]));
        $this->assertTrue($scan->events()->where('title', 'Orçamento da fase esgotado')->exists());
        $this->assertFalse($scan->events()->where('title', 'Orçamento reservado para a verificação de configuração')->exists());

        foreach (['/servicos/vulneravel/busca', '/servicos/vulneravel/consulta', '/servicos/vulneravel/pedido'] as $route) {
            $this->invokeJob($job, 'runner', ['/probe', ['path' => $route]]);
        }
        $this->invokeJob($job, 'observe', [false]);

        $this->assertSame(3, $ledger->summary()['probers']['spent']);
        $this->assertSame(3, $scan->fresh()->request_count);
    }

    public function test_large_budgets_only_hold_what_the_hunt_and_the_cross_proof_can_use(): void
    {
        config(['egide.hunt.max_steps' => 60]);
        $accounts = ['a' => ['email' => 'a@empresa.test'], 'b' => ['email' => 'b@empresa.test']];
        foreach ([[$accounts, 1337, 60], [['a' => $accounts['a']], 1397, 0]] as [$credentials, $probers, $cross]) {
            $scan = Scan::create(['user_id' => User::factory()->create()->id, 'name' => 'Homologação', 'mode' => 'external', 'status' => 'running',
                'scope' => ['lab' => false, 'env_type' => 'test', 'url' => 'https://app.example.com/'], 'credentials' => $credentials,
                'provider' => 'anthropic', 'budget' => 2000]);
            $job = new RunScan($scan->id);
            $this->prepare($job, ['scan' => $scan]);
            $ledger = $this->invokeJob($job, 'openLedger');

            $ledger->begin('observacao');
            $ledger->spend(100);
            $ledger->begin('probers');
            $this->assertSame($probers, $ledger->remaining());
            $ledger->spend($probers);
            $ledger->begin('caca');
            $this->assertGreaterThanOrEqual(60 * 8, $ledger->remaining());
            $ledger->spend($ledger->remaining());
            $ledger->begin('prova_cruzada');
            $this->assertSame($cross, $ledger->remaining());
            $this->assertSame($cross === 0, $ledger->summary()['prova_cruzada']['closed']);
        }
    }

    public function test_external_session_imports_the_surface_and_records_the_phase_budget(): void
    {
        $this->fakeAnthropic();
        $scan = $this->externalScan();
        $job = new FakeRunScan($scan->id);

        $this->executeJob($job);

        $scan->refresh();
        $this->assertSame('completed', $scan->status, (string) $scan->error);
        $this->assertSame('mapped', $scan->result);

        $start = $job->calls[0][1];
        $this->assertSame('mapeamento', $start['safety']);
        $this->assertSame('egide-'.substr(str_replace('-', '', $scan->id), 0, 12), $start['session_tag']);
        $this->assertSame([], $start['approved_writes']);
        $this->assertNull($start['max_rps']);

        $imported = $scan->events()->where('title', 'Superfície importada')->sole();
        $this->assertSame(2, $imported->data['count']);
        $this->assertSame('openapi', $imported->data['format']);
        $this->assertStringContainsString('OpenAPI', $imported->detail);

        $this->assertSame('low', $scan->summary['risk']);
        $this->assertSame('Mapeamento concluído sem achados.', $scan->summary['summary']);
        $surface = $scan->summary['superficie'];
        $this->assertGreaterThanOrEqual(2, $surface['vistas']);
        $this->assertSame(2, $surface['por_origem']['openapi']);
        $this->assertIsInt($surface['testadas']);

        $books = $scan->events()->where('title', 'Orçamento por fase')->sole();
        $this->assertSame('system', $books->type);
        $this->assertSame(['input' => 200, 'output' => 40], $books->data['tokens']);
        $this->assertSame(array_keys(BudgetLedger::PHASES), array_keys($books->data['duracao_s']));
        $this->assertSame(180, $books->data['fases']['total']['budget']);
        $this->assertSame((int) $scan->request_count, $books->data['fases']['total']['spent'] + $books->data['fora_de_fase']);
        $this->assertLessThan(
            $scan->events()->where('title', 'Sessão concluída')->value('id'),
            $books->id,
        );

        Http::assertSent(fn ($request) => ! str_contains($request['system'], 'resumo executivo')
            && (json_decode($request['messages'][0]['content'], true)['foco_do_cliente'] ?? null) === self::FOCUS);
        Http::assertNotSent(fn ($request) => str_contains($request['system'], 'resumo executivo')
            && array_key_exists('foco_do_cliente', (array) json_decode($request['messages'][0]['content'], true)));
    }

    public function test_scan_lists_its_hypotheses(): void
    {
        $scan = $this->labScan();
        $other = $this->labScan();
        foreach ([$scan, $scan, $other] as $owner) {
            Hypothesis::create(['scan_id' => $owner->id, 'class' => 'bola', 'method' => 'GET', 'path' => '/api/faturas/{id}',
                'oracle' => 'canario_cruzado', 'action_class' => 'leitura']);
        }

        $this->assertSame(2, $scan->hypotheses()->count());
        $this->assertSame([$scan->id], $scan->hypotheses()->pluck('scan_id')->unique()->values()->all());
    }

    public function test_planner_accumulates_token_usage_per_session(): void
    {
        Http::fake([
            'api.openai.com/*' => Http::response([
                'output' => [['content' => [['type' => 'output_text', 'text' => '{"choice":0}']]]],
                'usage' => ['input_tokens' => 70, 'output_tokens' => 5],
            ]),
            'openrouter.ai/*' => Http::response([
                'choices' => [['message' => ['content' => '{"choice":0}']]],
                'usage' => ['prompt_tokens' => 11, 'completion_tokens' => 3],
            ]),
        ]);
        $planner = new Planner;
        $choices = [['kind' => 'click', 'control' => 1, 'label' => 'Abrir faturas']];
        $openai = new Scan(['provider' => 'openai', 'model' => 'modelo', 'engine_key' => 'chave']);
        $router = new Scan(['provider' => 'openrouter', 'model' => 'modelo', 'engine_key' => 'chave']);

        $planner->select($openai, 'Escolha.', [], $choices);
        $planner->select($openai, 'Escolha.', [], $choices);
        $planner->select($router, 'Escolha.', [], $choices);

        $this->assertSame(['input' => 140, 'output' => 10], $planner->tokens($openai));
        $this->assertSame(['input' => 11, 'output' => 3], $planner->tokens($router));
        $this->assertSame(['input' => 0, 'output' => 0], $planner->tokens(new Scan(['provider' => 'openai'])));
        Http::assertNotSent(fn ($request) => str_contains($request->body(), 'foco_do_cliente'));
    }
}
