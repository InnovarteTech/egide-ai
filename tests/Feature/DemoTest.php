<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\ApiToken;
use App\Models\Monitor;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Models\Workspace;
use Database\Seeders\DatabaseSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\RateLimiter;
use Tests\TestCase;

class DemoTest extends TestCase
{
    use RefreshDatabase;

    private function enableDemo(array $overrides = []): void
    {
        config(['egide.demo_access' => true, 'egide.demo_daily_per_user' => 2, 'egide.demo_daily_total' => 100, ...$overrides]);
        $this->platformEngine('anthropic', 'claude-sonnet-5-5', 'platform-key', 1);
    }

    public function test_public_demo_requires_a_configured_platform_engine(): void
    {
        config(['egide.demo_access' => true]);
        $this->post('/laboratorio/entrar')->assertNotFound();

        $this->enableDemo();
        $this->post('/laboratorio/entrar')->assertRedirect('/');
        $this->assertTrue(Workspace::sole()->demo);
    }

    public function test_demo_sessions_use_the_platform_engine_without_storing_it_on_the_workspace(): void
    {
        Queue::fake();
        $this->enableDemo();
        $this->post('/laboratorio/entrar');

        $this->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertRedirect();

        $scan = Scan::sole();
        $this->assertSame('anthropic', $scan->provider);
        $this->assertSame('claude-sonnet-5-5', $scan->model);
        $this->assertSame('platform-key', $scan->engine_key);
        $this->assertNull(Workspace::sole()->api_key);
        Queue::assertPushed(RunScan::class);
    }

    public function test_demo_accounts_are_limited_to_the_laboratory_and_a_daily_quota(): void
    {
        Queue::fake();
        $this->enableDemo();
        $this->post('/laboratorio/entrar');

        $this->post('/sessoes', ['mode' => 'external', 'target_id' => 1, 'authorized' => true])->assertSessionHasErrors('mode');
        $this->put('/configuracoes', ['name' => 'X'])->assertSessionHasErrors('name');

        $this->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertSessionHasNoErrors();
        Scan::query()->update(['status' => 'completed']);
        $this->post('/sessoes', ['mode' => 'retest', 'agent' => true])->assertSessionHasNoErrors();
        Scan::query()->update(['status' => 'completed']);
        $this->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertSessionHasErrors('mode');
        $this->assertSame(2, Scan::count());
    }

    public function test_old_demo_accounts_are_removed_but_regular_accounts_stay(): void
    {
        $this->enableDemo();
        $this->post('/laboratorio/entrar');
        $this->post('/sair');
        $regular = User::factory()->create(['created_at' => now()->subDays(3)]);
        User::whereKeyNot($regular->id)->update(['created_at' => now()->subDays(2)]);

        $this->artisan('egide:demo-limpeza')->assertSuccessful();

        $this->assertSame([$regular->id], User::pluck('id')->all());
    }

    public function test_demo_visitors_are_read_only_outside_the_laboratory(): void
    {
        $this->enableDemo();
        $this->post('/laboratorio/entrar');

        $this->post('/ambientes', ['name' => 'X', 'origin' => 'https://empresa.com', 'entry_path' => '/', 'rules' => 'GET /*'])->assertSessionHas('notice');
        $this->post('/sentinela', ['name' => 'Monitor'])->assertSessionHas('notice');
        $this->post('/configuracoes/tokens', ['name' => 'CI'])->assertSessionHas('notice');
        $this->put('/configuracoes/webhook', ['webhook_url' => 'https://hooks.example.com/x'])->assertSessionHas('notice');

        $this->assertSame(0, Target::count() + Monitor::count() + ApiToken::count());
        $this->assertNull(Workspace::sole()->webhook_url);
        $this->get('/sentinela')->assertOk();
    }

    public function test_demo_accounts_are_capped_per_address_and_globally(): void
    {
        $this->enableDemo(['egide.demo_accounts_per_ip' => 2, 'egide.demo_max_accounts' => 100]);
        foreach (range(1, 3) as $attempt) {
            $this->post('/laboratorio/entrar');
            $this->post('/sair');
        }
        $this->assertSame(2, Workspace::count());

        config(['egide.demo_max_accounts' => 2, 'egide.demo_accounts_per_ip' => 50]);
        RateLimiter::clear('demo-account:127.0.0.1');
        $this->post('/laboratorio/entrar')->assertSessionHasErrors('email');
        $this->assertSame(2, Workspace::count());
    }

    public function test_demo_quota_counts_only_ai_sessions_and_one_active_session(): void
    {
        Queue::fake();
        $this->enableDemo(['egide.demo_daily_per_user' => 10, 'egide.demo_daily_total' => 1]);
        $this->post('/laboratorio/entrar');

        $this->post('/sessoes', ['mode' => 'laboratory'])->assertSessionHasNoErrors();
        $this->post('/sessoes', ['mode' => 'laboratory'])->assertSessionHasErrors('mode');
        Scan::query()->update(['status' => 'completed']);
        $this->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertSessionHasNoErrors();
        Scan::query()->update(['status' => 'completed']);
        $this->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertSessionHasErrors('mode');

        $this->assertSame(['lab', 'anthropic'], Scan::orderBy('created_at')->pluck('provider')->all());
    }

    public function test_stuck_sessions_are_closed_and_cleanup_spares_running_ones(): void
    {
        $this->enableDemo();
        $this->post('/laboratorio/entrar');
        $user = User::sole();
        $scan = Scan::create(['user_id' => $user->id, 'name' => 'x', 'mode' => 'laboratory', 'status' => 'running', 'scope' => [], 'started_at' => now()->subMinutes(20)]);
        User::query()->update(['created_at' => now()->subDays(2)]);

        $this->artisan('egide:demo-limpeza')->assertSuccessful();
        $this->assertSame(1, User::count());

        $this->artisan('egide:sessoes-presas')->assertSuccessful();
        $this->assertSame('failed', $scan->fresh()->status);
        $this->artisan('egide:demo-limpeza')->assertSuccessful();
        $this->assertSame(0, User::count());
    }

    public function test_seeder_never_promotes_an_existing_account(): void
    {
        $existing = User::factory()->create(['email' => 'admin@egide.test']);
        $this->seed(DatabaseSeeder::class);

        $this->assertFalse((bool) $existing->fresh()->is_admin);
    }
}
