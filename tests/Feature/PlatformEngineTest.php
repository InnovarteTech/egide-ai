<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Platform;
use App\Models\Scan;
use App\Models\User;
use App\Models\Workspace;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class PlatformEngineTest extends TestCase
{
    use RefreshDatabase;

    private function admin(): User
    {
        $admin = User::factory()->create();
        $admin->forceFill(['is_admin' => true])->save();

        return $admin;
    }

    public function test_only_admins_configure_the_engine_and_the_key_is_never_exposed(): void
    {
        $engine = ['provider' => 'anthropic', 'model' => 'claude-sonnet-5-5', 'api_key' => 'sk-ant-secret-key-1234', 'daily_limit' => 5];
        $this->actingAs(User::factory()->create())->put('/admin/motor', $engine)->assertNotFound();
        $this->assertSame('lab', Platform::current()->ai_provider);

        $admin = $this->admin();
        $this->actingAs($admin)->put('/admin/motor', $engine)->assertSessionHasNoErrors();

        $platform = Platform::current();
        $this->assertSame('sk-ant-secret-key-1234', $platform->ai_key);
        $this->assertSame(5, $platform->ai_daily_limit);
        $this->assertStringNotContainsString('sk-ant-secret', (string) DB::table('platform_settings')->value('ai_key'));

        $this->actingAs($admin)->get('/admin')->assertDontSee('sk-ant-secret')
            ->assertInertia(fn (Assert $page) => $page->component('Admin', false)
                ->where('engine.keyHint', '…1234')->where('engine.ready', true)->missing('engine.ai_key'));

        $this->actingAs($admin)->put('/admin/motor', [...$engine, 'api_key' => null, 'daily_limit' => 8])->assertSessionHasNoErrors();
        $this->assertSame('sk-ant-secret-key-1234', Platform::current()->ai_key);

        $this->actingAs($admin)->put('/admin/motor', ['provider' => 'openai', 'model' => '', 'daily_limit' => 8])
            ->assertSessionHasErrors(['model', 'api_key']);

        $this->actingAs($admin)->put('/admin/motor', ['provider' => 'lab', 'daily_limit' => 8])->assertSessionHasNoErrors();
        $this->assertNull(Platform::current()->ai_key);
    }

    public function test_workspaces_use_the_platform_engine_and_cannot_set_their_own(): void
    {
        Queue::fake();
        $user = User::factory()->create();
        $this->actingAs($user)->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertSessionHasErrors('agent');

        $this->actingAs($user)->put('/configuracoes', [
            'name' => 'Time azul', 'provider' => 'openai', 'model' => 'x', 'api_key' => 'workspace-key',
        ])->assertSessionHasNoErrors();
        $workspace = Workspace::sole();
        $this->assertSame('Time azul', $workspace->name);
        $this->assertNull($workspace->api_key);

        $this->platformEngine('openrouter', 'anthropic/claude-sonnet-5-5', 'platform-key');
        $this->actingAs($user)->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertSessionHasNoErrors();

        $scan = Scan::sole();
        $this->assertSame('openrouter', $scan->provider);
        $this->assertSame('platform-key', $scan->engine_key);
        Queue::assertPushed(RunScan::class);
    }

    public function test_daily_limit_applies_to_ai_sessions_of_regular_accounts_only(): void
    {
        Queue::fake();
        $this->platformEngine(limit: 1);
        $user = User::factory()->create();

        $this->actingAs($user)->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertSessionHasNoErrors();
        Scan::query()->update(['status' => 'failed']);
        $this->actingAs($user)->post('/sessoes', ['mode' => 'retest', 'agent' => true])->assertSessionHasNoErrors();
        Scan::query()->update(['status' => 'completed', 'request_count' => 12]);
        $this->actingAs($user)->post('/sessoes', ['mode' => 'laboratory', 'agent' => true])->assertSessionHasErrors('mode');
        $this->actingAs($user)->post('/sessoes', ['mode' => 'retest'])->assertSessionHasNoErrors();
        $this->assertSame(['anthropic', 'anthropic', 'lab'], Scan::pluck('provider')->sort()->values()->all());

        $admin = $this->admin();
        foreach (['laboratory', 'retest'] as $mode) {
            $this->actingAs($admin)->post('/sessoes', ['mode' => $mode, 'agent' => true])->assertSessionHasNoErrors();
            Scan::query()->update(['status' => 'completed', 'request_count' => 12]);
        }
        $this->assertSame(2, Scan::where('user_id', $admin->id)->count());
    }

    public function test_connection_check_reports_success_and_provider_errors(): void
    {
        $admin = $this->admin();
        Http::fake(['api.anthropic.com/v1/messages' => Http::sequence()
            ->push(['stop_reason' => 'end_turn', 'content' => [['type' => 'text', 'text' => '{"ok":true}']]])
            ->push(['error' => ['message' => 'invalid x-api-key']], 401)]);
        $engine = ['provider' => 'anthropic', 'model' => 'claude-sonnet-5-5', 'api_key' => 'test-key'];

        $this->actingAs($admin)->post('/admin/motor/testar', $engine)->assertSessionHasNoErrors()->assertSessionHas('notice');
        $this->actingAs($admin)->post('/admin/motor/testar', $engine)->assertSessionHasErrors('api_key');
        $this->assertSame('lab', Platform::current()->ai_provider);
        Http::assertSent(fn ($request) => $request->hasHeader('x-api-key', 'test-key'));
    }
}
