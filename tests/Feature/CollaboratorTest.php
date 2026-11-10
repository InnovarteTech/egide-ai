<?php

namespace Tests\Feature;

use App\Models\CollaboratorHit;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Tests\TestCase;

class CollaboratorTest extends TestCase
{
    use RefreshDatabase;

    public function test_collaborator_ingestion_records_and_isolates(): void
    {
        $this->get('/api/colaborador/tokenAAAAAA')->assertNoContent();
        $this->post('/api/colaborador/tokenBBBBBB', ['x' => 1])->assertNoContent();

        $this->assertSame(1, CollaboratorHit::where('token', 'tokenAAAAAA')->count());
        $this->assertSame(1, CollaboratorHit::where('token', 'tokenBBBBBB')->count());
        $this->assertSame(0, CollaboratorHit::where('token', 'tokenCCCCCC')->count());
        $this->assertSame('GET', CollaboratorHit::where('token', 'tokenAAAAAA')->sole()->method);

        // token too short → route does not match (404), no hit stored.
        $this->get('/api/colaborador/short')->assertNotFound();
        $this->assertSame(0, CollaboratorHit::where('token', 'short')->count());
    }

    public function test_callback_caps_rows_per_token(): void
    {
        $this->withoutMiddleware(ThrottleRequests::class);
        for ($i = 0; $i < 70; $i++) {
            $this->get('/api/colaborador/tokenCAP0001');
        }
        $count = CollaboratorHit::where('token', 'tokenCAP0001')->count();
        $this->assertGreaterThan(0, $count);
        $this->assertLessThanOrEqual(50, $count);
    }
}
