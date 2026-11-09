<?php

namespace Tests\Feature;

use App\Http\Controllers\AdminController;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class AdminTest extends TestCase
{
    use RefreshDatabase;

    private function admin(): User
    {
        $user = User::factory()->create();
        $user->forceFill(['is_admin' => true])->save();

        return $user;
    }

    public function test_regular_users_cannot_reach_the_admin_area(): void
    {
        $this->actingAs(User::factory()->create())->get('/admin')->assertNotFound();
        $this->post('/admin/parar-tudo')->assertNotFound();
    }

    public function test_admin_can_stop_every_active_session(): void
    {
        $owner = User::factory()->create();
        $running = Scan::create(['user_id' => $owner->id, 'name' => 'A', 'mode' => 'laboratory', 'status' => 'running', 'scope' => []]);
        $done = Scan::create(['user_id' => $owner->id, 'name' => 'B', 'mode' => 'laboratory', 'status' => 'completed', 'scope' => []]);

        $this->actingAs($this->admin())->post('/admin/parar-tudo')->assertRedirect();

        $this->assertNotNull($running->fresh()->stop_requested_at);
        $this->assertNull($done->fresh()->stop_requested_at);
    }

    public function test_global_pause_blocks_new_sessions(): void
    {
        Queue::fake();
        Cache::forever(AdminController::PAUSED, true);

        $this->actingAs(User::factory()->create())->post('/sessoes', ['mode' => 'laboratory'])->assertSessionHasErrors('mode');

        Queue::assertNothingPushed();
        Cache::forget(AdminController::PAUSED);
    }

    public function test_suspended_account_is_signed_out_and_its_sessions_stop(): void
    {
        $user = User::factory()->create();
        $scan = Scan::create(['user_id' => $user->id, 'name' => 'A', 'mode' => 'laboratory', 'status' => 'running', 'scope' => []]);

        $this->actingAs($this->admin())->post('/admin/usuarios/'.$user->id.'/suspensao', ['suspended' => true])->assertRedirect();

        $this->assertNotNull($user->fresh()->suspended_at);
        $this->assertNotNull($scan->fresh()->stop_requested_at);
        $this->actingAs($user->fresh())->get('/')->assertRedirect('/entrar');
    }
}
