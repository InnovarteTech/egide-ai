<?php

namespace Tests\Feature;

use App\Jobs\NotifyScan;
use App\Jobs\RunScan;
use App\Models\ApiToken;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Models\Workspace;
use App\Security\Launcher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use ReflectionMethod;
use Tests\TestCase;

class AutomationTest extends TestCase
{
    use RefreshDatabase;

    private function token(User $user): string
    {
        $token = ApiToken::issue();
        ApiToken::create(['user_id' => $user->id, 'name' => 'CI', 'token_hash' => ApiToken::hash($token), 'prefix' => substr($token, 0, 14)]);

        return $token;
    }

    private function target(User $user, array $extra = []): Target
    {
        return Target::create([
            'user_id' => $user->id, 'name' => 'Homologação', 'origin' => 'https://staging.invalid',
            'entry_path' => '/', 'verification_token' => str_repeat('a', 48),
            'rules' => [['method' => 'GET', 'path' => '/', 'prefix' => true]], 'denied' => [],
            'verified_at' => now(), ...$extra,
        ]);
    }

    private function scan(Target $target, array $extra = []): Scan
    {
        return Scan::create([
            'user_id' => $target->user_id, 'target_id' => $target->id, 'name' => $target->name, 'mode' => 'external',
            'status' => 'completed', 'provider' => 'anthropic', 'scope' => ['url' => $target->origin.'/', 'lab' => false, 'rules' => [], 'denied' => []],
            'finished_at' => now(), ...$extra,
        ]);
    }

    public function test_api_requires_a_valid_token(): void
    {
        $this->getJson('/api/v1/ativos')->assertStatus(401);
        $this->withToken('escapi_invalido')->getJson('/api/v1/ativos')->assertStatus(401);

        $user = User::factory()->create();
        $token = $this->token($user);
        $this->withToken($token)->getJson('/api/v1/ativos')->assertOk()->assertJson(['ativos' => []]);
        $this->assertNotNull(ApiToken::sole()->last_used_at);
    }

    public function test_api_is_isolated_between_accounts(): void
    {
        $owner = User::factory()->create();
        $target = $this->target($owner);
        $scan = $this->scan($target);
        $other = $this->token(User::factory()->create());

        $this->withToken($other)->postJson('/api/v1/sessoes', ['ativo' => $target->id])->assertNotFound();
        $this->withToken($other)->getJson('/api/v1/sessoes/'.$scan->id)->assertNotFound();
        $this->withToken($other)->getJson('/api/v1/ativos')->assertJson(['ativos' => []]);
    }

    public function test_api_reports_scan_status_and_finding_counts(): void
    {
        $user = User::factory()->create();
        $target = $this->target($user);
        $scan = $this->scan($target, ['result' => 'exposure', 'summary' => ['risk' => 'high', 'summary' => 'x', 'priorities' => []]]);
        $scan->findings()->create(['title' => 'A', 'severity' => 'high', 'category' => 'x', 'evidence' => [], 'remediation' => 'y']);
        $scan->findings()->create(['title' => 'B', 'severity' => 'low', 'category' => 'x', 'evidence' => [], 'remediation' => 'y']);

        $this->withToken($this->token($user))->getJson('/api/v1/sessoes/'.$scan->id)->assertOk()->assertJson([
            'status' => 'completed', 'resultado' => 'exposure', 'risco' => 'high',
            'achados' => ['critical' => 0, 'high' => 1, 'medium' => 0, 'low' => 1],
        ]);
    }

    public function test_api_refuses_to_launch_without_a_provider_or_while_another_session_runs(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        $target = $this->target($user);
        $token = $this->token($user);

        $this->withToken($token)->postJson('/api/v1/sessoes', ['ativo' => $target->id])
            ->assertStatus(409)->assertJsonPath('error', 'O motor de IA da plataforma ainda não foi configurado pelo administrador.');

        $this->platformEngine();
        $this->scan($target, ['status' => 'running']);
        $this->withToken($token)->postJson('/api/v1/sessoes', ['ativo' => $target->id])
            ->assertStatus(409)->assertJsonPath('error', 'Já existe uma sessão em andamento para este ambiente.');
        Queue::assertNotPushed(RunScan::class);
    }

    public function test_tokens_are_shown_once_and_revocable_only_by_owner(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->post('/configuracoes/tokens', ['name' => 'GitHub'])->assertSessionHas('api_token');
        $token = ApiToken::sole();
        $this->assertSame(ApiToken::hash(session('api_token')), $token->token_hash);

        $this->actingAs(User::factory()->create())->delete('/configuracoes/tokens/'.$token->id)->assertNotFound();
        $this->actingAs($user)->delete('/configuracoes/tokens/'.$token->id)->assertRedirect();
        $this->assertSame(0, ApiToken::count());
    }

    public function test_schedule_requires_verification_and_retries_later_on_failure(): void
    {
        $user = User::factory()->create();
        $pending = $this->target($user, ['verified_at' => null, 'origin' => 'https://pendente.invalid']);
        $this->actingAs($user)->put('/ambientes/'.$pending->id.'/agenda', ['schedule' => 'daily'])->assertSessionHasErrors('schedule');

        $target = $this->target($user);
        $this->actingAs($user)->put('/ambientes/'.$target->id.'/agenda', ['schedule' => 'weekly'])->assertSessionHasNoErrors();
        $this->assertSame('weekly', $target->fresh()->schedule);

        $this->artisan('egide:agendadas')->assertSuccessful();
        $this->assertTrue($target->fresh()->next_run_at->isAfter(now()->addMinutes(50)));
        $this->assertSame(0, Scan::count());
    }

    public function test_new_findings_against_the_previous_session_are_a_regression(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        Workspace::create(['user_id' => $user->id, 'webhook_url' => 'https://hooks.example.com/x']);
        $target = $this->target($user);
        $previous = $this->scan($target, ['finished_at' => now()->subDay()]);
        $previous->findings()->create(['title' => 'HSTS ausente', 'severity' => 'medium', 'category' => 'x', 'evidence' => [], 'remediation' => 'y']);
        $current = $this->scan($target);
        $current->findings()->create(['title' => 'HSTS ausente', 'severity' => 'medium', 'category' => 'x', 'evidence' => [], 'remediation' => 'y']);
        $current->findings()->create(['title' => 'Arquivo .env exposto publicamente', 'severity' => 'critical', 'category' => 'x', 'evidence' => [], 'remediation' => 'y']);

        $job = new RunScan($current->id);
        $property = new \ReflectionProperty($job, 'scan');
        $property->setValue($job, $current);
        (new ReflectionMethod($job, 'afterCompletion'))->invoke($job);

        $this->assertTrue($current->fresh()->regression);
        Queue::assertPushed(NotifyScan::class, fn (NotifyScan $notify) => $notify->newFindings === ['Arquivo .env exposto publicamente']);
    }

    public function test_configuration_findings_on_another_route_are_not_a_regression(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        $target = $this->target($user);
        $previous = $this->scan($target, ['finished_at' => now()->subDay(), 'result' => 'protected']);
        $previous->findings()->create(['title' => 'HSTS ausente', 'severity' => 'medium', 'category' => 'x', 'evidence' => ['kind' => 'config', 'path' => '/login'], 'remediation' => 'y']);
        $challenge = $this->scan($target, ['finished_at' => now()->subHour(), 'result' => 'challenge']);
        $current = $this->scan($target, ['result' => 'protected']);
        $current->findings()->create(['title' => 'HSTS ausente', 'severity' => 'medium', 'category' => 'x', 'evidence' => ['kind' => 'config', 'path' => '/painel'], 'remediation' => 'y']);

        $job = new RunScan($current->id);
        (new \ReflectionProperty($job, 'scan'))->setValue($job, $current);
        (new ReflectionMethod($job, 'afterCompletion'))->invoke($job);

        $this->assertFalse($current->fresh()->regression);
    }

    public function test_suspended_owner_cannot_launch_scheduled_sessions(): void
    {
        $user = User::factory()->create(['suspended_at' => now()]);
        $target = $this->target($user);

        $this->expectExceptionMessage('suspensa');
        app(Launcher::class)->external($target, 'schedule');
    }

    public function test_local_targets_are_refused_outside_local_mode(): void
    {
        $user = User::factory()->create();
        $base = ['name' => 'Local', 'entry_path' => '/', 'rules' => 'GET /'];

        $this->actingAs($user)->post('/ambientes', [...$base, 'origin' => 'https://app.local.egide.test', 'local_port' => 8080])
            ->assertSessionHasErrors('local_port');
        $this->actingAs($user)->post('/ambientes', [...$base, 'origin' => 'https://app.local.egide.test'])
            ->assertSessionHasErrors('origin');
        $this->assertSame(0, Target::count());
    }

    public function test_target_creation_rejects_reserved_ports_and_shared_record_paths(): void
    {
        $user = User::factory()->create();
        $base = ['name' => 'App', 'entry_path' => '/', 'rules' => 'GET /*'];

        $this->actingAs($user)->post('/ambientes', [...$base, 'origin' => 'https://app.local.egide.test', 'local_port' => 6379])
            ->assertSessionHasErrors('local_port');
        $this->actingAs($user)->post('/ambientes', [...$base, 'origin' => 'https://staging.empresa.com', 'email_a' => 'a@x.com', 'password_a' => 'x',
            'origin_a' => 'https://conta.local.egide.test'])->assertSessionHasErrors('origin_a');
        $this->actingAs($user)->post('/ambientes', [...$base, 'origin' => 'https://staging.empresa.com',
            'email_a' => 'a@x.com', 'password_a' => 'x', 'marker_a' => 'ESCOPO-0123456789ABCDEF', 'path_a' => '/api/pedidos/1',
            'email_b' => 'b@x.com', 'password_b' => 'y', 'marker_b' => 'ESCOPO-FEDCBA9876543210', 'path_b' => '/api/pedidos/1',
        ])->assertSessionHasErrors('path_b');
        $this->assertSame(0, Target::count());
    }

    public function test_each_session_takes_a_free_runner_and_waits_when_all_are_busy(): void
    {
        config(['egide.runner_urls' => ['http://runner-1:8791', 'http://runner-2:8791']]);
        $acquire = new ReflectionMethod(RunScan::class, 'acquireRunner');

        $first = $acquire->invoke($one = new RunScan('a'));
        $second = $acquire->invoke($two = new RunScan('b'));
        $third = $acquire->invoke(new RunScan('c'));

        $this->assertNotNull($first);
        $this->assertNotNull($second);
        $this->assertNull($third);
        $url = new \ReflectionProperty(RunScan::class, 'runnerUrl');
        $this->assertNotSame($url->getValue($one), $url->getValue($two));

        $first->release();
        $this->assertNotNull($acquire->invoke(new RunScan('d')));
    }
}
