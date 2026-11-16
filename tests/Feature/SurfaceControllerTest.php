<?php

namespace Tests\Feature;

use App\Http\Controllers\SurfaceController;
use App\Models\Target;
use App\Models\User;
use App\Models\Workspace;
use App\Security\SurfaceImport;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

class SurfaceControllerTest extends TestCase
{
    use RefreshDatabase;

    private const URI = 'ambientes/{target}/superficie';

    private ?string $address = '93.184.216.34';

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->bind(SurfaceController::class, fn () => new class(fn () => $this->address) extends SurfaceController
        {
            public function __construct(private \Closure $resolver) {}

            protected function publicAddress(string $url): ?string
            {
                return ($this->resolver)();
            }
        });
        foreach (['POST' => 'store', 'DELETE' => 'destroy'] as $method => $action) {
            if (! collect(Route::getRoutes()->get($method))->contains(fn ($route) => $route->uri() === self::URI)) {
                Route::middleware(['web', 'auth'])->match([$method], self::URI, [SurfaceController::class, $action]);
            }
        }
    }

    private function document(): string
    {
        return json_encode(['openapi' => '3.0.0', 'paths' => [
            '/api/pedidos/{id}' => ['get' => [], 'delete' => []],
            '/api/clientes' => ['get' => [], 'post' => []],
        ]]);
    }

    private function target(User $user, array $extra = []): Target
    {
        return Target::create([
            'user_id' => $user->id, 'name' => 'Loja', 'origin' => 'https://app.example.com', 'api_origin' => 'https://api.example.com',
            'entry_path' => '/', 'verification_token' => str_repeat('a', 48),
            'rules' => [['method' => 'GET', 'path' => '/', 'prefix' => true]], 'denied' => [], 'verified_at' => now(), ...$extra,
        ]);
    }

    private function stored(Target $target, string $column): ?array
    {
        return json_decode((string) Target::find($target->id)->getRawOriginal($column), true);
    }

    public function test_imports_an_uploaded_file_and_clears_it(): void
    {
        $user = User::factory()->create();
        $target = $this->target($user);
        $file = UploadedFile::fake()->createWithContent('openapi.json', $this->document());

        $this->actingAs($user)->from('/ambientes')->post('/ambientes/'.$target->id.'/superficie', ['arquivo' => $file])
            ->assertRedirect('/ambientes')->assertSessionHasNoErrors()->assertSessionHas('notice');
        $this->assertCount(4, $this->stored($target, 'surface'));
        $meta = $this->stored($target, 'surface_meta');
        $this->assertSame(['openapi', 'openapi.json', 'arquivo'], [$meta['format'], $meta['name'], $meta['via']]);

        $this->from('/ambientes')->delete('/ambientes/'.$target->id.'/superficie')->assertRedirect('/ambientes')->assertSessionHas('notice');
        $this->assertNull($this->stored($target, 'surface'));
        $this->assertNull($this->stored($target, 'surface_meta'));
    }

    public function test_only_serves_the_owner_rejects_bad_documents_and_blocks_the_demo(): void
    {
        $owner = User::factory()->create();
        $target = $this->target($owner);
        $file = fn () => UploadedFile::fake()->createWithContent('openapi.json', $this->document());

        $this->actingAs(User::factory()->create())->post('/ambientes/'.$target->id.'/superficie', ['arquivo' => $file()])->assertNotFound();
        $this->delete('/ambientes/'.$target->id.'/superficie')->assertNotFound();

        $this->actingAs($owner)->from('/ambientes')->post('/ambientes/'.$target->id.'/superficie', [
            'arquivo' => UploadedFile::fake()->createWithContent('lixo.json', '{"foo": 1}'),
        ])->assertRedirect('/ambientes')->assertSessionHasErrors('arquivo');
        $this->post('/ambientes/'.$target->id.'/superficie', [])->assertSessionHasErrors('arquivo');

        Workspace::create(['user_id' => $owner->id, 'name' => 'Demo', 'demo' => true]);
        $this->post('/ambientes/'.$target->id.'/superficie', ['arquivo' => $file()])->assertRedirect('/ambientes')->assertSessionHas('notice');
        $this->assertNull($this->stored($target, 'surface'));
    }

    public function test_downloads_only_from_verified_public_target_origins(): void
    {
        $this->withoutMiddleware(ThrottleRequests::class);
        Http::fake([
            'https://api.example.com/openapi.json*' => Http::response($this->document()),
            'https://api.example.com/grande.json' => Http::response(str_repeat(' ', SurfaceImport::MAX_BYTES + 10)),
            'https://api.example.com/redireciona.json' => Http::response('', 302, ['Location' => 'https://evil.example.org/x']),
            '*' => Http::response('{}', 500),
        ]);
        $user = User::factory()->create();
        $target = $this->target($user);
        $post = fn (string $url, ?Target $other = null) => $this->actingAs($user)->from('/ambientes')
            ->post('/ambientes/'.($other ?? $target)->id.'/superficie', ['url' => $url]);

        foreach (['https://evil.example.org/openapi.json', 'http://api.example.com/openapi.json', 'https://api.example.com:8443/openapi.json',
            'https://usuario:senha@api.example.com/openapi.json', 'https://api.example.com/grande.json', 'https://api.example.com/redireciona.json'] as $url) {
            $post($url)->assertSessionHasErrors('url');
        }
        $unverified = $this->target($user, ['origin' => 'https://outro.example.com', 'api_origin' => null, 'verified_at' => null]);
        $post('https://outro.example.com/openapi.json', $unverified)->assertSessionHasErrors('url');
        $this->assertNull($this->stored($target, 'surface'));
        Http::assertNotSent(fn ($request) => ! str_starts_with($request->url(), 'https://api.example.com/'));

        $post('https://api.example.com/openapi.json?token=segredo')->assertSessionHasNoErrors()->assertSessionHas('notice');
        $meta = $this->stored($target, 'surface_meta');
        $this->assertSame(['https://api.example.com/openapi.json', 'url', 4], [$meta['name'], $meta['via'], $meta['count']]);

        $this->address = null;
        $post('https://api.example.com/openapi.json')->assertSessionHasErrors('url');
        $this->assertCount(1, Http::recorded(fn ($request) => str_starts_with($request->url(), 'https://api.example.com/openapi.json')));
    }
}
