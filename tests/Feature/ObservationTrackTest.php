<?php

namespace Tests\Feature;

use App\Jobs\NotifyScan;
use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Models\Workspace;
use App\Security\Planner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Inertia\Testing\AssertableInertia;
use Tests\TestCase;

class ObservationTrackTest extends TestCase
{
    use RefreshDatabase;

    private function target(User $user): Target
    {
        return Target::create([
            'user_id' => $user->id, 'name' => 'Homologação', 'origin' => 'https://staging.invalid', 'entry_path' => '/',
            'verification_token' => str_repeat('a', 48), 'rules' => [['method' => 'GET', 'path' => '/', 'prefix' => true]],
            'denied' => [], 'verified_at' => now(),
        ]);
    }

    private function scan(Target $target, array $extra = []): Scan
    {
        return Scan::create([
            'user_id' => $target->user_id, 'target_id' => $target->id, 'name' => $target->name, 'mode' => 'external',
            'status' => 'completed', 'provider' => 'anthropic', 'model' => 'claude-teste', 'engine_key' => 'chave',
            'scope' => ['url' => $target->origin.'/', 'lab' => false, 'rules' => [], 'denied' => []], 'finished_at' => now(), ...$extra,
        ]);
    }

    private function finding(Scan $scan, string $title, string $severity, string $track = 'achado', array $evidence = []): void
    {
        $scan->findings()->create(['title' => $title, 'severity' => $severity, 'category' => 'x', 'evidence' => $evidence, 'remediation' => 'y', 'track' => $track]);
    }

    private function job(Scan $scan): RunScan
    {
        $job = new RunScan($scan->id);
        $property = new \ReflectionProperty($job, 'scan');
        $property->setAccessible(true);
        $property->setValue($job, $scan);

        return $job;
    }

    private function invoke(RunScan $job, string $method, array $arguments = []): mixed
    {
        $reflection = new \ReflectionMethod($job, $method);
        $reflection->setAccessible(true);

        return $reflection->invoke($job, ...$arguments);
    }

    public function test_observations_never_count_as_a_regression(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        Workspace::create(['user_id' => $user->id, 'webhook_url' => 'https://hooks.example.com/x']);
        $target = $this->target($user);
        $previous = $this->scan($target, ['finished_at' => now()->subDay()]);
        $this->finding($previous, 'HSTS ausente', 'medium');
        $this->finding($previous, 'Arquivo .env exposto publicamente', 'critical', 'observacao');
        $current = $this->scan($target);
        $this->finding($current, 'HSTS ausente', 'medium');
        $this->finding($current, 'Resposta divergente sem marcador', 'high', 'observacao');

        $this->invoke($this->job($current), 'afterCompletion');
        $this->assertFalse((bool) $current->fresh()->regression);
        Queue::assertPushed(NotifyScan::class, fn (NotifyScan $notify) => $notify->newFindings === []);

        $this->finding($current, 'Arquivo .env exposto publicamente', 'critical');
        $this->invoke($this->job($current), 'afterCompletion');
        $this->assertTrue($current->fresh()->regression);
        Queue::assertPushed(NotifyScan::class, fn (NotifyScan $notify) => $notify->newFindings === ['Arquivo .env exposto publicamente']);
    }

    public function test_executive_summary_risk_floor_and_facts_ignore_observations(): void
    {
        Http::fake(['api.anthropic.com/*' => Http::response(['stop_reason' => 'end_turn', 'content' => [['type' => 'text',
            'text' => json_encode(['risk' => 'none', 'summary' => 'Resumo.', 'priorities' => []])]]])]);
        $scan = $this->scan($this->target(User::factory()->create()), ['status' => 'running']);
        $this->finding($scan, 'Cabeçalho CSP ausente', 'low');
        $this->finding($scan, 'Resposta divergente sem marcador', 'critical', 'observacao');

        $this->invoke($this->job($scan), 'executiveSummary', [new Planner, 'mapped']);

        $this->assertSame('low', $scan->fresh()->summary['risk']);
        Http::assertSent(fn ($request) => array_column(json_decode($request['messages'][0]['content'], true)['findings'], 'title') === ['Cabeçalho CSP ausente']);
    }

    public function test_retest_uses_the_original_cross_account_proof_not_an_observation(): void
    {
        $target = $this->target(User::factory()->create());
        $original = $this->scan($target, ['result' => 'exposure']);
        $this->finding($original, 'Divergência sem marcador', 'high', 'observacao', ['path' => '/pedidos/9', 'own_path' => '/pedidos/8']);
        $this->finding($original, 'XSS refletido', 'medium', 'achado', ['path' => '/busca']);
        $this->finding($original, 'Conta de teste acessa registro de outra conta', 'high', 'achado', ['path' => '/pedidos/12', 'own_path' => '/pedidos/34']);
        $retest = $this->scan($target, ['status' => 'running']);

        $proof = $this->invoke($this->job($retest), 'retestProof', [$original->id]);

        $this->assertSame(['path' => '/pedidos/12', 'own_path' => '/pedidos/34'], $proof);
        $this->assertNull($this->invoke($this->job($this->scan($this->target(User::factory()->create()))), 'retestProof', [$original->id]));
    }

    public function test_webhook_counts_only_proven_findings(): void
    {
        $scan = $this->scan($this->target(User::factory()->create()), ['summary' => ['risk' => 'high']]);
        $this->finding($scan, 'Conta de teste acessa registro de outra conta', 'high');
        $this->finding($scan, 'Cabeçalho CSP ausente', 'low');
        $this->finding($scan, 'Resposta divergente sem marcador', 'critical', 'observacao');

        $payload = (new NotifyScan($scan->id))->payload($scan);

        $this->assertSame(['critical' => 0, 'high' => 1, 'medium' => 0, 'low' => 1], $payload['scan']['findings']);
        $this->assertStringEndsWith('· 2 achado(s)', $payload['text']);
    }

    public function test_admin_counters_ignore_observations(): void
    {
        $owner = User::factory()->create();
        $scan = $this->scan($this->target($owner));
        $this->finding($scan, 'Conta de teste acessa registro de outra conta', 'high');
        $this->finding($scan, 'Resposta divergente sem marcador', 'critical', 'observacao');
        $admin = User::factory()->create();
        $admin->forceFill(['is_admin' => true])->save();

        $this->actingAs($admin)->get('/admin')->assertOk()->assertInertia(fn (AssertableInertia $page) => $page
            ->where('stats.severity', ['high' => 1])
            ->where('users', fn ($users) => collect($users)->firstWhere('id', $owner->id)['findings'] === 1));
    }
}
