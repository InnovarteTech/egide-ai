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
        if ($path === '/dom_probe') {
            $token = (string) ($data['token'] ?? '');

            return ['executed' => $this->vulnerable, 'token' => $this->vulnerable ? $token : null];
        }
        if ($path !== '/probe') {
            return ['network' => [], 'actor' => 'a'];
        }
        $inject = $data['inject'] ?? null;
        $value = is_array($inject) ? (string) ($inject['value'] ?? '') : '';
        $route = (string) ($data['path'] ?? '');
        $safe = ['sample' => 'ok', 'type' => 'application/json', 'status' => 200, 'elapsed' => 50];
        // domXssSweep probes (no inject): entry HTML + bundle with a source-fed sink.
        if ($value === '' && str_contains($route, 'vulneravel') && ! str_contains($route, '.js')) {
            return ['sample' => '<html><script src="/assets/app.js"></script></html>', 'type' => 'text/html', 'status' => 200, 'elapsed' => 40];
        }
        if ($value === '' && str_contains($route, '.js')) {
            return ['sample' => 'var h = location.hash.slice(1); el.dangerouslySetInnerHTML = {__html: h};', 'type' => 'application/javascript', 'status' => 200, 'elapsed' => 40];
        }
        if (! $this->vulnerable) {
            return $safe;
        }
        if ((str_contains($value, '$ne') || str_contains($value, '$gt')) && str_contains($route, 'consulta')) {
            return ['sample' => 'MongoServerError: unknown top level operator: $ne', 'type' => 'application/json', 'status' => 500, 'elapsed' => 50];
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
        if (in_array($value, ["'", '"', "')", "';"], true) && str_contains($route, 'consulta')) {
            return ['sample' => 'Fatal error: SQLSTATE[42000]: Syntax error or access violation near "\'"', 'type' => 'application/json', 'status' => 500, 'elapsed' => 50];
        }
        if (str_contains($value, 'etc/passwd') && str_contains($route, 'arquivo')) {
            return ['sample' => "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", 'type' => 'text/plain', 'status' => 200, 'elapsed' => 50];
        }
        if (str_contains($route, 'graphql') && str_contains($value, '__schema')) {
            return ['sample' => '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}', 'type' => 'application/json', 'status' => 200, 'elapsed' => 50];
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
            'POST /servicos/vulneravel/login' => ['method' => 'POST', 'path' => '/servicos/vulneravel/login', 'params' => [], 'body' => ['email', 'senha'], 'auth' => false, 'seen_in' => 'xhr'],
            'GET /servicos/vulneravel/arquivo' => ['method' => 'GET', 'path' => '/servicos/vulneravel/arquivo', 'params' => ['file'], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
            'POST /servicos/vulneravel/graphql' => ['method' => 'POST', 'path' => '/servicos/vulneravel/graphql', 'params' => [], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'],
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

        $save = $reflection->getMethod('saveCoverage');
        $save->setAccessible(true);
        $save->invoke($fake);

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

    public function test_get_probes_never_assert_login_rate_limit(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $this->assertNotContains('AuthCheck · sem limite de tentativas', $scan->findings()->pluck('category')->all());
    }

    public function test_agentic_loop_finds_wave2_vulnerabilities(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $categories = $scan->findings()->pluck('category')->all();
        $this->assertContains('InjectionCheck · SQLi por erro', $categories);
        $this->assertContains('InjectionCheck · path traversal', $categories);
        $this->assertContains('InventoryCheck · GraphQL introspection', $categories);
    }

    public function test_agentic_loop_finds_dom_xss_and_nosql(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $categories = $scan->findings()->pluck('category')->all();
        $this->assertContains('InjectionCheck · DOM XSS', $categories);
        $this->assertContains('InjectionCheck · NoSQL', $categories);
    }

    public function test_clientscan_static_coverage_never_claims_falha(): void
    {
        $scan = $this->runLoop(vulnerable: true);
        $static = array_values(array_filter((array) $scan->coverage, fn ($c) => $c['check'] === 'ClientScan · sinks DOM'));
        $this->assertNotEmpty($static);
        $this->assertNotSame('falha', $static[0]['verdict']);
    }
}
