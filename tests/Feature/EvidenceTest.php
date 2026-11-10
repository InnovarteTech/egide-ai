<?php

namespace Tests\Feature;

use App\Models\Finding;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class EvidenceTest extends TestCase
{
    use RefreshDatabase;

    private function finding(User $owner): Finding
    {
        $scan = Scan::create(['user_id' => $owner->id, 'name' => 'Lab', 'mode' => 'laboratory', 'scope' => ['lab' => true], 'status' => 'completed']);

        return $scan->findings()->create(['title' => 'XSS', 'severity' => 'high', 'category' => 'InjectionCheck · XSS refletido', 'evidence' => ['path' => '/busca', 'screenshot' => true], 'remediation' => 'escapar']);
    }

    public function test_owner_sees_the_screenshot_taken_when_the_finding_was_proved(): void
    {
        Storage::fake();
        $owner = User::factory()->create();
        $finding = $this->finding($owner);
        Storage::put('findings/'.$finding->id.'.jpg', "\xff\xd8prova");

        $this->actingAs($owner)->get('/achados/'.$finding->id.'/imagem')->assertOk()->assertHeader('Content-Type', 'image/jpeg');
    }

    public function test_other_accounts_never_see_someone_elses_evidence(): void
    {
        Storage::fake();
        $finding = $this->finding(User::factory()->create());
        Storage::put('findings/'.$finding->id.'.jpg', "\xff\xd8prova");

        $this->actingAs(User::factory()->create())->get('/achados/'.$finding->id.'/imagem')->assertNotFound();
    }

    public function test_missing_screenshot_is_not_found(): void
    {
        Storage::fake();
        $owner = User::factory()->create();

        $this->actingAs($owner)->get('/achados/'.$this->finding($owner)->id.'/imagem')->assertNotFound();
    }
}
