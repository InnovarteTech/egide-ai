<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Security\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ScopeGateTest extends TestCase
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

    public function test_account_role_is_stored_and_exposed_to_scope(): void
    {
        $this->actingAs(User::factory()->create())->post('/ambientes', $this->environment([
            'role_a' => 'admin', 'role_b' => 'normal',
        ]))->assertSessionHasNoErrors();

        $target = Target::sole();
        $this->assertSame('admin', $target->credentials['a']['role']);
        $this->assertSame('normal', $target->credentials['b']['role']);

        $scope = Scope::launch($target);
        $this->assertSame('admin', $scope['accounts']['a']['role']);
        $this->assertSame('normal', $scope['accounts']['b']['role']);
    }

    public function test_account_role_defaults_to_normal_and_rejects_bad_values(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->post('/ambientes', $this->environment())->assertSessionHasNoErrors();
        $this->assertSame('normal', Target::sole()->credentials['a']['role']);

        $this->actingAs(User::factory()->create())->post('/ambientes', $this->environment([
            'origin' => 'https://b.example.com', 'api_origin' => '', 'path_a' => '/bookings/12', 'role_a' => 'root',
        ]))->assertSessionHasErrors('role_a');
    }

    public function test_production_scope_never_carries_a_write_rule(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->post('/ambientes', $this->environment([
            'write_test' => '1', 'environment_type' => 'production',
        ]))->assertSessionHasNoErrors();
        $prod = Target::sole();
        $this->assertTrue($prod->write_test);
        $this->assertNull(Scope::launch($prod)['write']);

        $this->actingAs(User::factory()->create())->post('/ambientes', $this->environment([
            'origin' => 'https://t.example.com', 'api_origin' => '', 'path_a' => '/bookings/12', 'path_b' => '/bookings/34',
            'write_test' => '1', 'environment_type' => 'test',
        ]))->assertSessionHasNoErrors();
        $test = Target::where('origin', 'https://t.example.com')->sole();
        $this->assertNotNull(Scope::launch($test)['write']);
    }

    private function aggressiveAllowed(array $scope): bool
    {
        $scan = new Scan(['scope' => $scope]);
        $job = new RunScan('x');
        $ref = new \ReflectionClass($job);
        $prop = $ref->getProperty('scan');
        $prop->setAccessible(true);
        $prop->setValue($job, $scan);
        $method = $ref->getMethod('aggressiveAllowed');
        $method->setAccessible(true);

        return $method->invoke($job);
    }

    private function aggressiveAllowedWith(array $credentials, array $scope): bool
    {
        $scan = new Scan(['scope' => $scope, 'credentials' => $credentials]);
        $job = new RunScan('x');
        $ref = new \ReflectionClass($job);
        $prop = $ref->getProperty('scan');
        $prop->setAccessible(true);
        $prop->setValue($job, $scan);
        $method = $ref->getMethod('aggressiveAllowed');
        $method->setAccessible(true);

        return $method->invoke($job);
    }

    private function invokePrivate(string $method, array $args)
    {
        $job = new RunScan('x');
        $ref = new \ReflectionMethod($job, $method);
        $ref->setAccessible(true);

        return $ref->invoke($job, ...$args);
    }

    public function test_aggressive_gate_fails_closed(): void
    {
        // Explicit test → allowed. Lab → allowed. Production, missing, or garbage → blocked (fail closed).
        $this->assertTrue($this->aggressiveAllowed(['env_type' => 'test']));
        $this->assertTrue($this->aggressiveAllowed(['lab' => true]));
        $this->assertFalse($this->aggressiveAllowed(['env_type' => 'production']));
        $this->assertFalse($this->aggressiveAllowed([]));
        $this->assertFalse($this->aggressiveAllowed(['env_type' => 'homolog']));
        $this->assertFalse($this->aggressiveAllowed(['env_type' => null]));
    }

    public function test_aggressive_battery_is_not_gated_on_account_count(): void
    {
        // The deep creative battery (mapExternal + agenticBattery) now runs whenever the env is
        // aggressive-eligible, whether the scan has one account or two. Account count never gates it;
        // only the env does. A second account adds the cross-account proof — it does not unlock the battery.
        $this->assertTrue($this->aggressiveAllowedWith(['a' => ['email' => 'a@x']], ['env_type' => 'test']));
        $this->assertTrue($this->aggressiveAllowedWith(
            ['a' => ['email' => 'a@x'], 'b' => ['email' => 'b@x']], ['env_type' => 'test']
        ));
        // Production stays mapping-only regardless of how many accounts are configured (fail closed).
        $this->assertFalse($this->aggressiveAllowedWith(['a' => ['email' => 'a@x']], ['env_type' => 'production']));
        $this->assertFalse($this->aggressiveAllowedWith(
            ['a' => ['email' => 'a@x'], 'b' => ['email' => 'b@x']], ['env_type' => 'production']
        ));
    }

    private function authSucceeded(array $network): bool
    {
        $job = new RunScan('x');
        $ref = new \ReflectionMethod($job, 'authSucceeded');
        $ref->setAccessible(true);

        return $ref->invoke($job, ['network' => $network]);
    }

    public function test_auth_succeeded_only_trusts_a_successful_auth_write(): void
    {
        // A write (POST/PUT/PATCH) to an auth path with 2xx is the one real signal of a login.
        $this->assertTrue($this->authSucceeded([['method' => 'POST', 'path' => '/api/auth/login', 'status' => 200]]));
        $this->assertTrue($this->authSucceeded([['method' => 'PUT', 'path' => '/session', 'status' => 204]]));

        // Everything that merely looks auth-ish but does not prove a login must NOT count:
        $this->assertFalse($this->authSucceeded([['method' => 'GET', 'path' => '/assets/login.css', 'status' => 200]]), 'asset GET');
        $this->assertFalse($this->authSucceeded([['method' => 'GET', 'path' => '/api/session', 'status' => 200]]), 'session GET');
        $this->assertFalse($this->authSucceeded([['method' => 'GET', 'path' => '/login', 'status' => 302]]), 'redirect back to login');
        $this->assertFalse($this->authSucceeded([['method' => 'POST', 'path' => '/api/auth/login', 'status' => 401]]), 'bad credentials');
        $this->assertFalse($this->authSucceeded([['method' => 'POST', 'path' => '/api/auth/login', 'status' => 422]]), 'validation error');
        $this->assertFalse($this->authSucceeded([['method' => 'POST', 'path' => '/api/orders', 'status' => 200]]), 'non-auth write');
        $this->assertFalse($this->authSucceeded([]), 'no traffic');
    }

    public function test_auth_paths_are_skipped_by_race_and_prototype_probes(): void
    {
        foreach ([
            '/api/auth/login', '/login', '/logout', '/api/session', '/api/sessions', '/logins', '/api/tokens',
            '/passwords', '/reset-password', '/entrar', '/auth/token', '/oauth/authorize', '/api/v2/authenticate', '/mfa/verify',
        ] as $path) {
            $this->assertTrue($this->invokePrivate('isAuthPath', [$path]), $path.' deveria ser tratada como rota de auth');
        }
        foreach (['/api/tickets', '/api/appointments', '/api/sectors', '/api/tickets/42'] as $path) {
            $this->assertFalse($this->invokePrivate('isAuthPath', [$path]), $path.' não é rota de auth');
        }
    }

    public function test_destructive_route_filter_covers_pt_br_and_english_verbs(): void
    {
        foreach ([
            '/usuarios/excluir', '/conta/deletar', '/item/remove', '/sessao/logout', '/user/desativar',
            '/registro/inativar', '/acesso/bloquear', '/cadastro/descadastrar', '/pedido/cancelar',
            '/token/revoke', '/senha/reset', '/perfil/sair', '/dado/apagar',
        ] as $route) {
            $this->assertTrue($this->invokePrivate('destructiveRoute', [$route]), $route.' deve ser destrutiva');
        }
        foreach (['/bookings/12', '/servicos/busca?q=1', '/painel/dados', '/relatorio/export', '/pedidos/123'] as $route) {
            $this->assertFalse($this->invokePrivate('destructiveRoute', [$route]), $route.' nao deve ser destrutiva');
        }
    }

    private function unsaved(array $attributes = []): Target
    {
        return new Target([
            'origin' => 'https://app.example.com', 'entry_path' => '/', 'environment_type' => 'test',
            'rules' => [['method' => 'GET', 'path' => '/', 'prefix' => true]], 'denied' => [], 'credentials' => [],
            ...$attributes,
        ]);
    }

    public function test_launch_forces_mapping_outside_test_environments_and_honours_the_target_mode(): void
    {
        $this->assertSame('mapeamento', Scope::launch($this->unsaved(['environment_type' => 'production', 'safety' => 'livre']))['safety']);
        $this->assertSame('mapeamento', Scope::launch($this->unsaved(['environment_type' => null, 'safety' => 'canario']))['safety']);
        $this->assertSame('canario', Scope::launch($this->unsaved())['safety']);
        $this->assertSame('livre', Scope::launch($this->unsaved(['safety' => 'livre']))['safety']);
        $this->assertSame('mapeamento', Scope::launch($this->unsaved(['safety' => 'mapeamento']))['safety']);
        $this->assertSame('canario', Scope::launch($this->unsaved(['safety' => 'lab']))['safety'], 'alvo real nunca roda sem as travas do proxy');
    }

    public function test_launch_carries_approved_writes_rate_limit_and_client_focus(): void
    {
        $writes = [['method' => 'POST', 'path' => '/convites', 'prefix' => false]];
        $scope = Scope::launch($this->unsaved(['approved_writes' => $writes, 'max_rps' => '2.50', 'focus' => '  '.'Priorize o módulo de faturas.'.'  ']));

        $this->assertSame($writes, $scope['approved_writes']);
        $this->assertSame(2.5, $scope['max_rps']);
        $this->assertSame('Priorize o módulo de faturas.', $scope['focus']);

        $raw = $this->unsaved();
        $raw->setRawAttributes([...$raw->getAttributes(), 'approved_writes' => json_encode($writes)]);
        $this->assertSame($writes, Scope::launch($raw)['approved_writes']);

        $bare = Scope::launch($this->unsaved(['focus' => str_repeat('a', 600)]));
        $this->assertSame([], $bare['approved_writes']);
        $this->assertNull($bare['max_rps']);
        $this->assertSame(500, mb_strlen($bare['focus']));
        $this->assertNull(Scope::launch($this->unsaved(['focus' => '   ', 'max_rps' => 0]))['focus']);
        $this->assertNull(Scope::launch($this->unsaved(['max_rps' => 0]))['max_rps']);
    }

    public function test_production_environment_skips_aggressive_checks(): void
    {
        $user = User::factory()->create();
        // Fail-safe default: a target created without an explicit choice is PRODUCTION → not aggressive-eligible.
        $this->actingAs($user)->post('/ambientes', $this->environment())->assertSessionHasNoErrors();
        $default = Target::sole();
        $this->assertSame('production', $default->environment_type);
        $this->assertSame('production', Scope::launch($default)['env_type']);
        $this->assertFalse($this->aggressiveAllowed(Scope::launch($default)));

        // Opting into test/homologation explicitly unlocks the aggressive battery.
        $this->actingAs(User::factory()->create())->post('/ambientes', $this->environment([
            'origin' => 'https://t.example.com', 'api_origin' => '', 'path_a' => '/bookings/12', 'environment_type' => 'test',
        ]))->assertSessionHasNoErrors();
        $test = Target::where('origin', 'https://t.example.com')->sole();
        $this->assertSame('test', $test->environment_type);
        $this->assertTrue($this->aggressiveAllowed(Scope::launch($test)));

        $this->actingAs(User::factory()->create())->post('/ambientes', $this->environment([
            'origin' => 'https://prod.example.com', 'api_origin' => '', 'path_a' => '/bookings/12',
            'environment_type' => 'production',
        ]))->assertSessionHasNoErrors();
        $prod = Target::where('origin', 'https://prod.example.com')->sole();
        $this->assertSame('production', $prod->environment_type);
        $this->assertSame('production', Scope::launch($prod)['env_type']);
        $this->assertFalse($this->aggressiveAllowed(Scope::launch($prod)));

        $this->actingAs(User::factory()->create())->post('/ambientes', $this->environment([
            'origin' => 'https://c.example.com', 'api_origin' => '', 'path_a' => '/bookings/12',
            'environment_type' => 'staging',
        ]))->assertSessionHasErrors('environment_type');
    }
}
