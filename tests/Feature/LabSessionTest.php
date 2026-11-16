<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\User;
use App\Security\Planner;
use App\Security\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class LabSessionTest extends TestCase
{
    use RefreshDatabase;

    public function test_lab_scope_lets_the_graphql_probe_through_the_proxy(): void
    {
        Queue::fake();
        $this->actingAs(User::factory()->create())->post('/sessoes', ['mode' => 'laboratory'])->assertRedirect();

        $scope = Scan::sole()->scope;
        $this->assertTrue(Scope::allows($scope, 'POST', '/servicos/vulneravel/graphql'));
        $this->assertFalse(Scope::allows($scope, 'POST', '/servicos/vulneravel/clientes'));
    }

    public function test_lab_sessions_accept_a_larger_request_budget_than_real_targets(): void
    {
        Queue::fake();
        $user = User::factory()->create();

        $this->actingAs($user)->post('/sessoes', ['mode' => 'laboratory', 'budget' => 600])->assertSessionHasNoErrors();
        $this->assertSame(600, Scan::sole()->budget);

        $this->actingAs($user)->post('/sessoes', ['mode' => 'retest', 'budget' => 601])->assertSessionHasErrors('budget');
        $this->actingAs($user)->post('/sessoes', ['mode' => 'external', 'budget' => 2001])->assertSessionHasErrors('budget');
    }

    private function haltedLabRun(string $provider = 'lab'): array
    {
        Storage::fake();
        $scan = Scan::create([
            'user_id' => User::factory()->create()->id, 'name' => 'Laboratório', 'mode' => 'laboratory', 'status' => 'queued',
            'scope' => ['lab' => true, 'url' => 'http://lab.egide.test:8788/vulneravel',
                'rules' => [['method' => '*', 'path' => '/', 'prefix' => true]], 'denied' => [], 'api' => null],
            'provider' => $provider, 'budget' => 600,
        ]);
        $job = new FakeRunScan($scan->id);
        $job->halt = ['reason' => 'Latência alta no alvo', 'at' => 1763100000];
        $execute = new \ReflectionMethod(RunScan::class, 'execute');
        $execute->setAccessible(true);
        $execute->invoke($job, new Planner);

        return [$scan, $job];
    }

    public function test_start_sends_the_session_tag_and_lab_mode_to_the_proxy(): void
    {
        [$scan, $job] = $this->haltedLabRun();

        [$path, $payload] = $job->calls[0];
        $this->assertSame('/start', $path);
        $this->assertSame('egide-'.substr(str_replace('-', '', $scan->id), 0, 12), $payload['session_tag']);
        $this->assertMatchesRegularExpression('/^egide-[0-9a-f]{12}$/D', $payload['session_tag']);
        $this->assertSame('lab', $payload['safety']);
        $this->assertSame(600, $payload['budget']);
    }

    public function test_hunt_minimum_is_released_up_front_when_the_session_cannot_hunt(): void
    {
        foreach (['lab' => true, 'openai' => false] as $provider => $released) {
            [$scan] = $this->haltedLabRun($provider);

            $phases = $scan->events()->where('title', 'Orçamento por fase')->sole()->data['fases'];
            $this->assertSame($released, $phases['caca']['closed'], $provider);
        }
    }
}
