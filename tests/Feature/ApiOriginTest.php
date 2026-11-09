<?php

namespace Tests\Feature;

use App\Models\Scan;
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

        $this->post('/ambientes', $this->environment(['write_test' => '1', 'environment_type' => 'test']))->assertSessionHasNoErrors();
        $target = Target::sole();
        $this->assertTrue($target->write_test);

        $scope = Scope::launch($target);
        $this->assertSame(['method' => 'PATCH', 'host' => 'api.example.com', 'path' => '/bookings/12', 'max' => 4], $scope['write']);

        $target->update(['write_test' => false]);
        $this->assertNull(Scope::launch($target)['write']);
    }

    public function test_registrable_domain_and_dns_verification_payload(): void
    {
        $this->assertSame('innovartetech.com.br', Scope::registrable('chiquinhosociety.innovartetech.com.br'));
        $this->assertSame('innovartetech.com.br', Scope::registrable('apiarenasmais.innovartetech.com.br'));
        $this->assertSame('example.com', Scope::registrable('api.staging.example.com'));
        $this->assertSame('example.com', Scope::registrable('example.com'));
        $this->assertSame('b.co.uk', Scope::registrable('a.b.co.uk'));

        $user = User::factory()->create();
        $this->actingAs($user)->post('/ambientes', $this->environment([
            'origin' => 'https://chiquinhosociety.innovartetech.com.br',
            'api_origin' => 'https://apiarenasmais.innovartetech.com.br',
            'path_a' => 'https://apiarenasmais.innovartetech.com.br/bookings/12',
        ]))->assertSessionHasNoErrors();
        $target = Target::sole();

        $this->assertSame(['innovartetech.com.br'], Scope::dnsDomains($target));
        $this->get('/ambientes')->assertInertia(fn ($page) => $page->component('Assets', false)
            ->where('targets.0.verify_dns', [[
                'domain' => 'innovartetech.com.br', 'host' => '_egide-verification',
                'name' => '_egide-verification.innovartetech.com.br', 'value' => $target->verification_token,
            ]]));
    }

    public function test_environment_update_preserves_token_and_password_and_delete_detaches_scans(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->post('/ambientes', $this->environment())->assertSessionHasNoErrors();
        $target = Target::sole();
        $token = $target->verification_token;
        $target->update(['verified_at' => now()]);
        $originalPassword = $target->credentials['a']['password'];

        // edit name + keep passwords blank (same emails) -> passwords preserved, token kept, stays verified (same origins)
        $this->put('/ambientes/'.$target->id, $this->environment([
            'name' => 'Arena+ renomeado', 'password_a' => '', 'password_b' => '',
        ]))->assertSessionHasNoErrors();
        $target->refresh();
        $this->assertSame('Arena+ renomeado', $target->name);
        $this->assertSame($token, $target->verification_token);
        $this->assertSame($originalPassword, $target->credentials['a']['password']);
        $this->assertNotNull($target->verified_at);

        // change the app origin -> must re-verify (verified_at cleared), token still kept
        $this->put('/ambientes/'.$target->id, $this->environment([
            'name' => 'Arena+ renomeado', 'origin' => 'https://outra.example.com', 'password_a' => '', 'password_b' => '',
        ]))->assertSessionHasNoErrors();
        $target->refresh();
        $this->assertNull($target->verified_at);
        $this->assertSame($token, $target->verification_token);

        // another user cannot edit or delete
        $this->actingAs(User::factory()->create())->put('/ambientes/'.$target->id, $this->environment())->assertNotFound();
        $this->delete('/ambientes/'.$target->id)->assertNotFound();

        // owner deletes -> target gone, its scan detached (kept in history)
        $scan = Scan::create([
            'user_id' => $user->id, 'target_id' => $target->id, 'name' => 'Sessão', 'mode' => 'external',
            'scope' => [], 'status' => 'completed',
        ]);
        $this->actingAs($user)->delete('/ambientes/'.$target->id)->assertRedirect();
        $this->assertDatabaseCount('targets', 0);
        $this->assertNull($scan->fresh()->target_id);
    }

    public function test_wildcard_scope_allows_every_method_except_blocked(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->post('/ambientes', $this->environment([
            'rules' => '* /*', 'denied' => '', 'path_a' => 'https://api.example.com/bookings/12', 'path_b' => '/bookings/34',
        ]))->assertSessionHasNoErrors();
        $scope = Scope::launch(Target::sole());
        foreach (['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as $method) {
            $this->assertTrue(Scope::allows($scope, $method, '/bookings/12'), $method);
            $this->assertTrue(Scope::allows($scope, $method, 'https://api.example.com/anything/here'), $method.' api');
        }

        // blocked paths still win over the wildcard
        $this->post('/ambientes', $this->environment([
            'name' => 'Arena 2', 'origin' => 'https://b.example.com', 'api_origin' => '',
            'rules' => '* /*', 'denied' => "/superadmin\n/platform", 'path_a' => '/bookings/12', 'path_b' => '/bookings/34',
        ]))->assertSessionHasNoErrors();
        $scope2 = Scope::launch(Target::where('origin', 'https://b.example.com')->sole());
        $this->assertTrue(Scope::allows($scope2, 'DELETE', '/bookings/9'));
        $this->assertFalse(Scope::allows($scope2, 'GET', '/superadmin'));
        $this->assertFalse(Scope::allows($scope2, 'POST', '/platform/tenants'));

        // prefix on an explicit write method is rejected
        $this->post('/ambientes', $this->environment(['name' => 'X', 'origin' => 'https://c.example.com', 'api_origin' => '', 'rules' => 'DELETE /*']))
            ->assertSessionHasErrors('rules');
    }
}
