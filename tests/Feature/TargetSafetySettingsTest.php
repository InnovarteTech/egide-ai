<?php

namespace Tests\Feature;

use App\Models\Target;
use App\Models\User;
use App\Models\Workspace;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class TargetSafetySettingsTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutMiddleware(ThrottleRequests::class);
    }

    private function form(array $extra = []): array
    {
        return [
            'name' => 'Homologação', 'origin' => 'https://staging.example.com', 'entry_path' => '/login',
            'rules' => "GET /login\nPOST /login\nGET /pedidos/*", 'environment_type' => 'test', ...$extra,
        ];
    }

    private function target(User $user, array $extra = []): Target
    {
        return Target::create([
            'user_id' => $user->id, 'name' => 'Loja', 'origin' => 'https://app.example.com', 'entry_path' => '/',
            'verification_token' => str_repeat('a', 48), 'rules' => [['method' => 'GET', 'path' => '/', 'prefix' => true]],
            'denied' => ['/pagamentos'], ...$extra,
        ]);
    }

    private function preflight(array $items): array
    {
        return collect($items)->keyBy('label')->all();
    }

    public function test_saves_safety_settings_for_a_test_environment(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)->post('/ambientes', $this->form([
            'safety' => 'livre', 'approved_writes' => "post /convites\n\nDELETE /reservas/*  ",
            'max_rps' => '2.5', 'focus' => '  Priorize o módulo de faturas.  ',
        ]))->assertRedirect()->assertSessionHasNoErrors();

        $target = Target::sole();
        $this->assertSame('livre', $target->safety);
        $this->assertSame([
            ['method' => 'POST', 'path' => '/convites', 'prefix' => false],
            ['method' => 'DELETE', 'path' => '/reservas', 'prefix' => true],
        ], $target->approved_writes);
        $this->assertSame(2.5, $target->max_rps);
        $this->assertSame('Priorize o módulo de faturas.', $target->focus);

        $this->put('/ambientes/'.$target->id, $this->form(['safety' => 'canario', 'approved_writes' => '', 'max_rps' => '', 'focus' => '']))
            ->assertSessionHasNoErrors();
        $target->refresh();
        $this->assertSame('canario', $target->safety);
        $this->assertNull($target->approved_writes);
        $this->assertNull($target->max_rps);
        $this->assertNull($target->focus);
    }

    public function test_new_targets_default_to_canary_and_production_ignores_the_safety_mode(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->post('/ambientes', $this->form())->assertSessionHasNoErrors();
        $this->assertSame('canario', Target::sole()->safety);

        $this->post('/ambientes', $this->form([
            'origin' => 'https://app.example.com', 'environment_type' => 'production',
            'safety' => 'livre', 'approved_writes' => 'POST /convites', 'max_rps' => '1', 'focus' => 'Leitura apenas.',
        ]))->assertSessionHasNoErrors();

        $production = Target::where('origin', 'https://app.example.com')->sole();
        $this->assertSame('canario', $production->safety);
        $this->assertNull($production->approved_writes);
        $this->assertSame(1.0, $production->max_rps);
        $this->assertSame('Leitura apenas.', $production->focus);
    }

    public function test_rejects_invalid_safety_settings(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user);
        $invalid = [
            ['safety' => 'destrutivo'], ['approved_writes' => 'GET /pedidos'], ['approved_writes' => 'POST /'],
            ['approved_writes' => 'POST /*'], ['approved_writes' => 'POST convites'], ['approved_writes' => 'POST /a b'],
            ['approved_writes' => 'POST /../admin'], ['approved_writes' => 'POST /'.str_repeat('a', 450)], ['approved_writes' => implode("\n", array_map(fn ($i) => 'POST /rota'.$i, range(1, 51)))],
            ['max_rps' => '0'], ['max_rps' => '50.5'], ['max_rps' => 'rápido'], ['focus' => str_repeat('x', 501)],
        ];

        foreach ($invalid as $fields) {
            $this->post('/ambientes', $this->form($fields))->assertSessionHasErrors(array_key_first($fields));
        }
        $this->assertDatabaseCount('targets', 0);
    }

    public function test_environment_screen_exposes_settings_and_never_the_full_surface(): void
    {
        $user = User::factory()->create();
        $this->target($user, [
            'environment_type' => 'test', 'safety' => 'livre', 'max_rps' => 3, 'focus' => 'Faturas',
            'approved_writes' => [['method' => 'POST', 'path' => '/convites', 'prefix' => false], ['method' => 'DELETE', 'path' => '/reservas', 'prefix' => true]],
            'surface' => [['method' => 'GET', 'path' => '/api/segredo-interno']],
            'surface_meta' => ['format' => 'openapi', 'count' => 1, 'name' => 'openapi.json', 'imported_at' => now()->toIso8601String()],
        ]);

        $response = $this->actingAs($user)->get('/ambientes')->assertOk()->assertDontSee('segredo-interno');
        $target = $response->viewData('page')['props']['targets'][0];

        $this->assertArrayNotHasKey('surface', $target);
        $this->assertArrayNotHasKey('credentials', $target);
        $this->assertSame(1, $target['surface_meta']['count']);
        $this->assertSame(['livre', "POST /convites\nDELETE /reservas/*", '3', 'Faturas'],
            [$target['edit']['safety'], $target['edit']['approved_writes'], $target['edit']['max_rps'], $target['edit']['focus']]);
    }

    public function test_preflight_reports_what_is_ready_and_what_is_missing(): void
    {
        $user = User::factory()->create();
        $this->platformEngine();
        $this->target($user, [
            'environment_type' => 'test', 'verified_at' => now()->subDays(3), 'safety' => 'canario',
            'credentials' => [
                'a' => ['email' => 'a@example.com', 'password' => 'x', 'path' => '/pedidos/1', 'role' => 'normal'],
                'b' => ['email' => 'b@example.com', 'password' => 'y', 'path' => '/pedidos/2', 'role' => 'admin'],
            ],
            'surface_meta' => ['format' => 'openapi', 'count' => 12, 'imported_at' => now()->toIso8601String()],
        ]);
        $this->target($user, ['origin' => 'https://outro.example.com', 'rules' => [], 'denied' => []]);

        $targets = collect($this->actingAs($user)->get('/ambientes')->viewData('page')['props']['targets'])->keyBy('origin');
        $ready = $this->preflight($targets['https://app.example.com']['preflight']);
        $missing = $this->preflight($targets['https://outro.example.com']['preflight']);

        $labels = ['Domínio verificado', 'Tipo de ambiente', 'Modo de segurança', 'Conta de teste A', 'Conta de teste B', 'Rota do registro', 'Superfície da API', 'Regras de escopo', 'Motor de IA'];
        $this->assertSame($labels, array_keys($ready));
        $this->assertTrue(collect($ready)->every(fn ($item) => $item['ok'] === true && is_string($item['detail']) && $item['detail'] !== ''));
        $this->assertStringContainsString('3 dias', $ready['Domínio verificado']['detail']);
        $this->assertStringContainsString('12 rotas', $ready['Superfície da API']['detail']);
        $this->assertStringContainsString('Canário', $ready['Modo de segurança']['detail']);
        $this->assertStringContainsString('escrita de teste configurada', $ready['Modo de segurança']['detail']);
        $this->assertStringNotContainsString('criados pela Égide', $ready['Modo de segurança']['detail']);

        foreach (['Domínio verificado', 'Conta de teste A', 'Conta de teste B', 'Rota do registro', 'Superfície da API', 'Regras de escopo'] as $label) {
            $this->assertFalse($missing[$label]['ok'], $label);
        }
        $this->assertStringContainsString('inconclusiva', $missing['Rota do registro']['detail']);
        $this->assertStringContainsString('mapeamento', $missing['Modo de segurança']['detail']);
    }

    public function test_preflight_flags_the_missing_ai_engine(): void
    {
        $user = User::factory()->create();
        $this->target($user, ['verified_at' => now()]);

        $preflight = $this->preflight($this->actingAs($user)->get('/sessoes/nova')->viewData('page')['props']['targets'][0]['preflight']);

        $this->assertFalse($preflight['Motor de IA']['ok']);
    }

    public function test_new_session_screen_carries_the_target_settings_and_preflight(): void
    {
        $user = User::factory()->create();
        $this->target($user, [
            'verified_at' => now(), 'environment_type' => 'test', 'safety' => 'livre', 'focus' => 'Faturas', 'max_rps' => 4.5,
            'surface' => [['method' => 'GET', 'path' => '/api/segredo-interno']], 'surface_meta' => ['format' => 'har', 'count' => 1],
        ]);

        $target = $this->actingAs($user)->get('/sessoes/nova')->assertDontSee('segredo-interno')->viewData('page')['props']['targets'][0];

        $this->assertSame(['livre', 'Faturas', 4.5, 'test', 1], [$target['safety'], $target['focus'], $target['max_rps'], $target['environment_type'], $target['surface_meta']['count']]);
        $this->assertArrayNotHasKey('surface', $target);
        $this->assertCount(9, $target['preflight']);
    }

    public function test_surface_routes_are_wired_with_throttle_and_demo_guard(): void
    {
        foreach (['POST', 'DELETE'] as $method) {
            $route = collect(Route::getRoutes()->get($method))->first(fn ($route) => $route->uri() === 'ambientes/{target}/superficie');
            $this->assertNotNull($route, $method);
            $this->assertContains('demo.readonly', $route->gatherMiddleware());
            $this->assertNotEmpty(array_filter($route->gatherMiddleware(), fn ($middleware) => str_starts_with($middleware, 'throttle:')));
        }

        $user = User::factory()->create();
        $target = $this->target($user, ['verified_at' => now()]);
        $document = json_encode(['openapi' => '3.0.0', 'paths' => ['/api/pedidos/{id}' => ['get' => []]]]);

        $this->actingAs($user)->from('/ambientes')
            ->post('/ambientes/'.$target->id.'/superficie', ['arquivo' => UploadedFile::fake()->createWithContent('openapi.json', $document)])
            ->assertRedirect('/ambientes')->assertSessionHasNoErrors();
        $this->assertSame(1, $target->fresh()->surface_meta['count']);

        $this->from('/ambientes')->delete('/ambientes/'.$target->id.'/superficie')->assertRedirect('/ambientes');
        $this->assertNull($target->fresh()->surface_meta);

        Workspace::create(['user_id' => $user->id, 'name' => 'Demo', 'demo' => true]);
        $this->from('/ambientes')
            ->post('/ambientes/'.$target->id.'/superficie', ['arquivo' => UploadedFile::fake()->createWithContent('openapi.json', $document)])
            ->assertRedirect('/ambientes')->assertSessionHas('notice');
        $this->assertNull($target->fresh()->surface_meta);
    }

    public function test_migration_marks_existing_test_environments_as_free(): void
    {
        $migration = require database_path('migrations/2026_11_14_000005_add_safety_to_targets.php');
        $migration->down();
        $this->assertFalse(Schema::hasColumns('targets', ['safety', 'approved_writes', 'max_rps', 'focus']));

        $user = User::factory()->create();
        foreach (['test' => 'https://teste.example.com', 'production' => 'https://prod.example.com'] as $type => $origin) {
            DB::table('targets')->insert([
                'user_id' => $user->id, 'name' => $type, 'origin' => $origin, 'verification_token' => 'token',
                'rules' => '[]', 'denied' => '[]', 'environment_type' => $type,
            ]);
        }

        $migration->up();

        $this->assertTrue(Schema::hasColumns('targets', ['safety', 'approved_writes', 'max_rps', 'focus']));
        $this->assertSame(['production' => 'canario', 'test' => 'livre'], DB::table('targets')->orderBy('name')->pluck('safety', 'name')->all());
    }
}
