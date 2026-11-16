<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Security\Planner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class EgideTest extends TestCase
{
    use RefreshDatabase;

    public function test_laboratory_session_is_queued_with_an_explicit_scope(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        $this->actingAs($user)->post('/sessoes', ['mode' => 'laboratory'])->assertRedirect();

        $scan = Scan::sole();
        $this->assertSame('queued', $scan->status);
        $this->assertTrue($scan->scope['lab']);
        $this->assertContains('/administracao', $scan->scope['denied']);
        Queue::assertPushed(RunScan::class, fn (RunScan $job) => $job->scanId === $scan->id);
    }

    public function test_laboratory_uses_the_platform_engine(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        $this->platformEngine();

        $this->actingAs($user)->post('/sessoes', ['mode' => 'retest', 'agent' => true])->assertRedirect();

        $scan = Scan::sole();
        $this->assertSame('anthropic', $scan->provider);
        $this->assertSame('test-model', $scan->model);
        $this->assertSame('test-key', $scan->engine_key);
        $this->assertTrue($scan->scope['lab']);
        Queue::assertPushed(RunScan::class, fn (RunScan $job) => $job->scanId === $scan->id);
    }

    public function test_agent_cannot_select_an_action_outside_the_offered_choices(): void
    {
        Http::fake(['api.openai.com/v1/responses' => Http::response([
            'output' => [['content' => [['type' => 'output_text', 'text' => '{"choice":9}']]]],
        ])]);

        $scan = new Scan(['provider' => 'openai', 'model' => 'test-model', 'engine_key' => 'test-key']);
        $this->expectExceptionMessage('A IA escolheu uma ação que o executor não ofereceu.');
        app(Planner::class)->select($scan, 'Escolha uma ação de teste.', [], [
            ['kind' => 'click', 'control' => 1, 'label' => 'Abrir faturas'],
        ]);
    }

    public function test_claude_decision_skips_thinking_blocks_and_requests_fallback(): void
    {
        Http::fake(['api.anthropic.com/v1/messages' => Http::response([
            'stop_reason' => 'end_turn',
            'content' => [['type' => 'thinking', 'thinking' => ''], ['type' => 'text', 'text' => '{"choice":1}']],
        ])]);

        $scan = new Scan(['provider' => 'anthropic', 'model' => 'claude-sonnet-5-5', 'engine_key' => 'test-key']);
        $choice = app(Planner::class)->select($scan, 'Escolha uma ação de teste.', [], [
            ['kind' => 'click', 'control' => 1, 'label' => 'Abrir painel'],
            ['kind' => 'click', 'control' => 2, 'label' => 'Abrir faturas'],
        ]);

        $this->assertSame('Abrir faturas', $choice['label']);
        Http::assertSent(fn ($request) => $request['fallbacks'] === 'default'
            && $request['output_config']['format']['type'] === 'json_schema'
            && $request->hasHeader('anthropic-beta', 'server-side-fallback-2026-07-01'));
    }

    public function test_executive_summary_is_validated_and_trimmed(): void
    {
        $priorities = ['Corrija a autorização por objeto', 'Ative HSTS', 'Defina CSP', 'Remova X-Powered-By', 'Ative nosniff', 'Item extra'];
        Http::fake(['api.anthropic.com/v1/messages' => Http::response([
            'stop_reason' => 'end_turn',
            'content' => [['type' => 'text', 'text' => json_encode(['risk' => 'high', 'summary' => '  Uma conta leu dados de outra.  ', 'priorities' => $priorities])]],
        ])]);

        $scan = new Scan(['provider' => 'anthropic', 'model' => 'claude-sonnet-5-5', 'engine_key' => 'test-key']);
        $summary = app(Planner::class)->summarize($scan, ['result' => 'exposure', 'findings' => []]);

        $this->assertSame('high', $summary['risk']);
        $this->assertSame('Uma conta leu dados de outra.', $summary['summary']);
        $this->assertCount(5, $summary['priorities']);
        Http::assertSent(fn ($request) => in_array('none', $request['output_config']['format']['schema']['properties']['risk']['enum'], true));
    }

    public function test_executive_summary_rejects_unknown_risk_levels(): void
    {
        Http::fake(['api.anthropic.com/v1/messages' => Http::response([
            'stop_reason' => 'end_turn',
            'content' => [['type' => 'text', 'text' => '{"risk":"catastrófico","summary":"x","priorities":[]}']],
        ])]);

        $scan = new Scan(['provider' => 'anthropic', 'model' => 'claude-sonnet-5-5', 'engine_key' => 'test-key']);
        $this->expectExceptionMessage('formato inválido');
        app(Planner::class)->summarize($scan, ['result' => 'mapped', 'findings' => []]);
    }

    public function test_claude_refusal_stops_the_decision(): void
    {
        Http::fake(['api.anthropic.com/v1/messages' => Http::response([
            'stop_reason' => 'refusal', 'stop_details' => ['type' => 'refusal', 'category' => 'cyber'], 'content' => [],
        ])]);

        $scan = new Scan(['provider' => 'anthropic', 'model' => 'claude-sonnet-5-5', 'engine_key' => 'test-key']);
        $this->expectExceptionMessage('O Claude recusou a decisão');
        app(Planner::class)->select($scan, 'Escolha uma ação de teste.', [], [
            ['kind' => 'click', 'control' => 1, 'label' => 'Abrir painel'],
        ]);
    }

    public function test_session_evidence_and_credentials_are_isolated_between_workspaces(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $scan = Scan::create([
            'user_id' => $owner->id, 'name' => 'Sessão privada', 'mode' => 'external',
            'scope' => ['url' => 'https://teste.example.com/'], 'engine_key' => 'secret-provider-key',
            'credentials' => ['a' => ['password' => 'secret-test-password']],
        ]);

        $this->actingAs($other)->getJson('/sessoes/'.$scan->id.'/eventos')->assertNotFound();
        $this->get('/sessoes/'.$scan->id.'/relatorio')->assertNotFound();
        $this->post('/sessoes/'.$scan->id.'/encerrar')->assertNotFound();

        $this->actingAs($owner)->getJson('/sessoes/'.$scan->id.'/eventos')
            ->assertOk()->assertJsonMissingPath('scan.engine_key')->assertJsonMissingPath('scan.credentials');
    }

    public function test_printable_report_is_owner_only_and_hides_secrets(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $scan = Scan::create([
            'user_id' => $owner->id, 'name' => 'Laboratório', 'mode' => 'laboratory', 'provider' => 'lab',
            'status' => 'completed', 'result' => 'exposure', 'engine_key' => 'secret-provider-key',
            'scope' => ['url' => 'http://lab.egide.test:8788/vulneravel', 'lab' => true, 'rules' => [], 'denied' => ['/administracao']],
        ]);
        $scan->findings()->create([
            'title' => 'Exposição', 'severity' => 'high', 'category' => 'BOLA',
            'evidence' => ['method' => 'GET', 'path' => '/x'], 'remediation' => 'Validar dono.',
        ]);
        $scan->findings()->create([
            'title' => 'Indício sem reprodução', 'severity' => 'critical', 'track' => 'observacao', 'category' => 'BOLA',
            'evidence' => ['method' => 'GET', 'path' => '/y'], 'remediation' => 'Revisar.',
        ]);

        $this->actingAs($other)->get('/sessoes/'.$scan->id.'/relatorio/imprimir')->assertNotFound();

        $this->actingAs($owner)->get('/sessoes/'.$scan->id.'/relatorio/imprimir')
            ->assertOk()->assertDontSee('secret-provider-key')
            ->assertInertia(fn ($page) => $page->component('Report', false)->has('findings', 1)->where('findings.0.cvss_score', 7.5)
                ->has('observations', 1)->where('observations.0.title', 'Indício sem reprodução')->where('engine', 'Roteiro do laboratório'));
        $this->getJson('/sessoes/'.$scan->id.'/relatorio')->assertOk()->assertJsonCount(1, 'findings')->assertJsonCount(1, 'observations');
    }

    public function test_sessions_and_findings_can_be_filtered(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $scope = ['url' => 'http://lab.egide.test:8788/vulneravel', 'lab' => true, 'rules' => [], 'denied' => []];
        $make = fn (User $user, string $status) => Scan::create([
            'user_id' => $user->id, 'name' => 'Laboratório', 'mode' => 'laboratory', 'provider' => 'lab', 'status' => $status, 'scope' => $scope,
        ]);
        $make($owner, 'running');
        $exposed = $make($owner, 'completed');
        $exposed->findings()->create(['title' => 'Exposição', 'severity' => 'high', 'category' => 'BOLA', 'evidence' => ['method' => 'GET', 'path' => '/x'], 'remediation' => 'Validar dono.']);
        $exposed->findings()->create(['title' => 'Cabeçalho', 'severity' => 'low', 'category' => 'Configuração', 'evidence' => ['method' => 'GET', 'path' => '/'], 'remediation' => 'Ajustar.']);
        $exposed->findings()->create(['title' => 'Indício', 'severity' => 'high', 'track' => 'observacao', 'category' => 'BOLA', 'evidence' => ['method' => 'GET', 'path' => '/z'], 'remediation' => 'Revisar.']);
        $make($owner, 'completed')->findings()->create(['title' => 'Só indício', 'severity' => 'critical', 'track' => 'observacao', 'category' => 'BOLA', 'evidence' => ['method' => 'GET', 'path' => '/w'], 'remediation' => 'Revisar.']);
        $make($other, 'running')->findings()->create(['title' => 'Alheio', 'severity' => 'high', 'category' => 'BOLA', 'evidence' => ['method' => 'GET', 'path' => '/y'], 'remediation' => 'x']);

        $this->actingAs($owner)->get('/sessoes?filtro=ativas')->assertInertia(fn ($page) => $page->component('Sessions', false)
            ->where('filter', 'ativas')->has('scans.data', 1)->where('counts', ['todas' => 3, 'ativas' => 1, 'achados' => 1]));
        $this->actingAs($owner)->get('/sessoes?filtro=achados')->assertInertia(fn ($page) => $page->component('Sessions', false)
            ->has('scans.data', 1)->where('scans.data.0.findings_count', 2));
        $this->actingAs($owner)->get('/sessoes?filtro=qualquer')->assertInertia(fn ($page) => $page->where('filter', 'todas')->has('scans.data', 3));

        $this->actingAs($owner)->get('/achados?severidade=high')->assertInertia(fn ($page) => $page->component('Findings', false)
            ->where('severity', 'high')->has('findings.data', 1)->where('findings.data.0.title', 'Exposição')
            ->where('counts', ['todas' => 2, 'critical' => 0, 'high' => 1, 'medium' => 0, 'low' => 1])
            ->has('observations', 2)->where('observationCount', 2));
    }

    public function test_unverified_target_cannot_be_queued(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        $this->platformEngine('openai', 'model', 'key');
        $target = Target::create([
            'user_id' => $user->id, 'name' => 'Staging', 'origin' => 'https://staging.example.com',
            'verification_token' => 'token', 'rules' => [], 'denied' => [],
        ]);

        $this->actingAs($user)->post('/sessoes', [
            'mode' => 'external', 'target_id' => $target->id, 'authorized' => true,
        ])->assertNotFound();

        Queue::assertNothingPushed();
    }

    public function test_two_account_configuration_requires_distinct_markers_and_hides_credentials(): void
    {
        $user = User::factory()->create();
        $data = [
            'name' => 'Staging', 'origin' => 'https://staging.example.com', 'entry_path' => '/login',
            'rules' => "GET /login\nPOST /login\nGET /documentos/*",
            'email_a' => 'a@example.com', 'email_b' => 'b@example.com',
            'password_a' => 'test-password-a', 'password_b' => 'test-password-b',
            'marker_a' => 'ESCOPO-0123456789ABCDEF', 'marker_b' => 'ESCOPO-0123456789ABCDEF',
        ];

        $this->actingAs($user)->post('/ambientes', $data)->assertSessionHasErrors('marker_b');
        $this->assertDatabaseCount('targets', 0);
        $data['marker_b'] = 'ESCOPO-FEDCBA9876543210';
        $this->post('/ambientes', $data)->assertRedirect()->assertSessionHasNoErrors();

        $target = Target::sole();
        $this->assertSame($data['marker_b'], $target->credentials['b']['marker']);
        $this->assertStringNotContainsString($data['password_b'], $target->getRawOriginal('credentials'));
        $this->assertArrayNotHasKey('credentials', $target->toArray());
    }

    public function test_external_retest_must_reference_a_finding_for_the_same_owned_target(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        $other = User::factory()->create();
        $this->platformEngine('openai', 'model', 'key');
        $target = Target::create([
            'user_id' => $user->id, 'name' => 'Staging', 'origin' => 'https://staging.example.com',
            'verification_token' => 'token', 'rules' => [], 'denied' => [], 'verified_at' => now(),
            'credentials' => ['a' => ['email' => 'a@example.com'], 'b' => ['email' => 'b@example.com']],
        ]);
        $unowned = Scan::create([
            'user_id' => $other->id, 'name' => 'Outro workspace', 'mode' => 'external',
            'scope' => [], 'status' => 'completed', 'result' => 'exposure',
        ]);

        $this->actingAs($user)->post('/sessoes', [
            'mode' => 'external', 'target_id' => $target->id, 'authorized' => true, 'retest_of' => $unowned->id,
        ])->assertSessionHasErrors('target_id');

        Queue::assertNothingPushed();
    }

    public function test_horizon_rejects_a_regular_workspace_user_even_in_local_mode(): void
    {
        $this->app->detectEnvironment(fn () => 'local');
        $user = User::factory()->create();

        $this->actingAs($user)->get('/horizon/api/stats')->assertForbidden();
    }

    public function test_overview_spotlights_the_running_session_with_its_findings(): void
    {
        $user = User::factory()->create();
        $done = Scan::create(['user_id' => $user->id, 'name' => 'Concluída', 'mode' => 'laboratory', 'status' => 'completed', 'provider' => 'lab', 'scope' => [], 'finished_at' => now()]);
        $done->findings()->create(['title' => 'X', 'severity' => 'high', 'category' => 'x', 'evidence' => [], 'remediation' => 'y']);
        $done->findings()->create(['title' => 'Indício', 'severity' => 'critical', 'track' => 'observacao', 'category' => 'x', 'evidence' => [], 'remediation' => 'y']);

        $this->actingAs($user)->get('/')->assertInertia(fn ($page) => $page->where('spotlight.id', $done->id)->where('spotlight.severity.high', 1)
            ->missing('spotlight.severity.critical')->where('stats.findings', 1));

        $running = Scan::create(['user_id' => $user->id, 'name' => 'Rodando', 'mode' => 'laboratory', 'status' => 'running', 'provider' => 'lab', 'scope' => []]);
        $running->event('browser', 'Ação selecionada pela IA', 'Ver faturas');
        $this->actingAs($user)->get('/')->assertInertia(fn ($page) => $page->where('spotlight.id', $running->id)->where('spotlight.events.0.detail', 'Ver faturas'));

        $other = User::factory()->create();
        $this->actingAs($other)->get('/')->assertInertia(fn ($page) => $page->where('spotlight', null));
    }
}
