<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\CollaboratorHit;
use App\Models\Scan;
use App\Models\User;
use App\Security\Planner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class FakeRunScan extends RunScan
{
    public bool $vulnerable = true;

    public bool $escaping = false;

    protected function observe(bool $saveFrame = true): array
    {
        return ['network' => [], 'actor' => 'a'];
    }

    protected function runner(string $path, array $data = []): array
    {
        if ($path !== '/probe') {
            return ['network' => [], 'actor' => 'a'];
        }
        $inject = $data['inject'] ?? null;
        $value = is_array($inject) ? (string) ($inject['value'] ?? '') : '';
        $route = (string) ($data['path'] ?? '');
        $safe = ['sample' => 'ok', 'type' => 'application/json', 'status' => 200, 'elapsed' => 50];
        if (! $this->vulnerable) {
            return $safe;
        }
        if (str_contains($value, 'egideXSS') && str_contains($route, 'busca')) {
            $reflected = $this->escaping ? htmlspecialchars($value, ENT_QUOTES) : $value;

            return ['sample' => '<div>'.$reflected.'</div>', 'type' => 'text/html', 'status' => 200, 'elapsed' => 50];
        }
        if ((stripos($value, 'sleep') !== false || str_contains($value, 'pg_sleep')) && str_contains($route, 'consulta')) {
            return ['sample' => '', 'type' => 'application/json', 'status' => 200, 'elapsed' => 6000];
        }
        if (str_contains($value, '/api/colaborador/') && str_contains($route, 'integrador')) {
            if (preg_match('~/api/colaborador/([A-Za-z0-9]+)~', $value, $match)) {
                CollaboratorHit::create(['token' => $match[1], 'method' => 'GET', 'source_ip' => '10.0.0.9', 'path' => '/fetch', 'received_at' => now()]);
            }

            return $safe;
        }

        return $safe;
    }
}

class AgenticLabTest extends TestCase
{
    use RefreshDatabase;

    private function runLoop(bool $vulnerable, bool $escaping = false): Scan
    {
        $user = User::factory()->create();
        $scan = Scan::create([
            'user_id' => $user->id, 'name' => 'Lab agêntico', 'mode' => 'laboratory', 'status' => 'running',
            'scope' => ['lab' => true, 'url' => 'http://lab.egide.test:8788/vulneravel',
                'rules' => [['method' => '*', 'path' => '/', 'prefix' => true]], 'denied' => [], 'api' => null],
            'provider' => 'lab', 'budget' => 80,
        ]);

        $fake = new FakeRunScan($scan->id);
        $fake->vulnerable = $vulnerable;
        $fake->escaping = $escaping;
        $inventory = [
            'GET /servicos/vulneravel/busca' => ['method' => 'GET', 'path' => '/servicos/vulneravel/busca', 'params' => ['q'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'GET /servicos/vulneravel/consulta' => ['method' => 'GET', 'path' => '/servicos/vulneravel/consulta', 'params' => ['id'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'GET /servicos/vulneravel/integrador' => ['method' => 'GET', 'path' => '/servicos/vulneravel/integrador', 'params' => ['url'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
        ];

        $reflection = new \ReflectionClass(RunScan::class);
        foreach (['scan' => $scan, 'inventory' => $inventory] as $property => $value) {
            $prop = $reflection->getProperty($property);
            $prop->setAccessible(true);
            $prop->setValue($fake, $value);
        }

        $method = $reflection->getMethod('agenticBattery');
        $method->setAccessible(true);
        $method->invoke($fake, new Planner);

        return $scan->fresh();
    }

    public function test_agentic_loop_finds_planted_vulnerabilities_with_proof(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $categories = $scan->findings()->pluck('category')->all();

        $this->assertContains('InjectionCheck · XSS refletido', $categories);
        $this->assertContains('InjectionCheck · SQLi por tempo', $categories);
        $this->assertContains('SSRF · callback out-of-band', $categories);
    }

    public function test_agentic_loop_reports_no_false_positive_on_fixed_variant(): void
    {
        $scan = $this->runLoop(vulnerable: false);
        $this->assertSame(0, $scan->findings()->count());
    }

    public function test_agentic_loop_does_not_flag_escaped_reflection(): void
    {
        $scan = $this->runLoop(vulnerable: true, escaping: true);
        $this->assertNotContains('InjectionCheck · XSS refletido', $scan->findings()->pluck('category')->all());
    }
}
