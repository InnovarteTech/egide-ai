<?php

namespace Tests\Feature;

use App\Models\Target;
use App\Models\User;
use App\Security\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ApiOriginTest extends TestCase
{
    use RefreshDatabase;

    private function environment(array $overrides = []): array
    {
        return [
            'name' => 'Arena+', 'origin' => 'https://arena.example.com', 'api_origin' => 'https://api.example.com',
            'entry_path' => '/admin/login', 'rules' => "GET /admin/*\nGET /bookings/*\nPOST /auth/login",
            'email_a' => 'a@example.com', 'password_a' => 'test-password-a',
            'email_b' => 'b@example.com', 'password_b' => 'test-password-b',
            'marker_a' => 'EGIDE-0123456789ABCDEF', 'marker_b' => 'EGIDE-FEDCBA9876543210',
            'path_a' => 'https://api.example.com/bookings/12', 'path_b' => '/bookings/34',
            ...$overrides,
        ];
    }

    public function test_environment_keeps_a_separate_api_domain_in_scope_and_verification(): void
    {
        $this->actingAs(User::factory()->create())->post('/ambientes', $this->environment(['api_origin' => 'https://API.example.com/']))
            ->assertSessionHasNoErrors();

        $target = Target::sole();
        $this->assertSame('https://api.example.com', $target->api_origin);
        $this->assertSame(['https://arena.example.com', 'https://api.example.com'], Scope::origins($target));
        $this->assertSame('https://api.example.com/bookings/12', $target->credentials['a']['path']);
        $this->assertSame('https://api.example.com/bookings/34', $target->credentials['b']['path']);

        $scope = Scope::launch($target);
        $this->assertSame('https://api.example.com', $scope['api']);
        $this->assertTrue(Scope::allows($scope, 'GET', 'https://api.example.com/bookings/12'));
        $this->assertTrue(Scope::allows($scope, 'GET', '/bookings/12'));
        $this->assertFalse(Scope::allows($scope, 'GET', 'https://other.example.com/bookings/12'));
        $this->assertFalse(Scope::allows($scope, 'GET', 'https://api.example.com/users/12'));
        $this->assertFalse(Scope::allows($scope, 'GET', 'https://api.example.com:8443/bookings/12'));
        $this->assertFalse(Scope::allows(['rules' => $scope['rules'], 'denied' => []], 'GET', 'https://api.example.com/bookings/12'));

        $this->get('/ambientes')->assertInertia(fn ($page) => $page->component('Assets', false)
            ->where('targets.0.verify_urls', [
                'https://arena.example.com/.well-known/egide-verification.txt',
                'https://api.example.com/.well-known/egide-verification.txt',
            ]));
    }

    public function test_api_domain_and_record_routes_are_validated(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->post('/ambientes', $this->environment(['api_origin' => 'http://api.example.com']))
            ->assertSessionHasErrors('api_origin');
        $this->post('/ambientes', $this->environment(['api_origin' => 'https://arena.example.com']))
            ->assertSessionHasErrors('api_origin');
        $this->post('/ambientes', $this->environment(['path_a' => 'https://evil.example.net/bookings/12']))
            ->assertSessionHasErrors('path_a');
        $this->post('/ambientes', $this->environment(['api_origin' => null]))->assertSessionHasErrors('path_a');
        $this->post('/ambientes', $this->environment(['origin_b' => 'ftp://b.example.com']))->assertSessionHasErrors('origin_b');
        $this->post('/ambientes', $this->environment(['api_origin' => 'https://api.local.egide.test']))->assertSessionHasErrors('api_origin');
        $this->assertDatabaseCount('targets', 0);

        $this->post('/ambientes', $this->environment(['api_origin' => '', 'path_a' => '/bookings/12']))->assertSessionHasNoErrors();
        $this->assertNull(Target::sole()->api_origin);
    }

    public function test_write_test_requires_two_accounts_and_a_record_and_scopes_the_write(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->post('/ambientes', $this->environment(['write_test' => '1', 'path_a' => '', 'path_b' => '']))
            ->assertSessionHasErrors('path_a');
        $this->assertDatabaseCount('targets', 0);

        $this->post('/ambientes', $this->environment(['write_test' => '1']))->assertSessionHasNoErrors();
        $target = Target::sole();
        $this->assertTrue($target->write_test);

        $scope = Scope::launch($target);
        $this->assertSame(['method' => 'PATCH', 'host' => 'api.example.com', 'path' => '/bookings/12', 'max' => 4], $scope['write']);

        $target->update(['write_test' => false]);
        $this->assertNull(Scope::launch($target)['write']);
    }
}
