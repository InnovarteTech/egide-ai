<?php

namespace Tests\Feature;

use App\Models\Scan;
use App\Models\User;
use App\Security\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
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
}
