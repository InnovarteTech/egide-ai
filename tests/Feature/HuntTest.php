<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class HuntTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake();
    }

    private ScriptedHunter $hunter;

    private FakeRunScan $fake;

    private function hunt(array $script, bool $vulnerable = true): Scan
    {
        $scan = Scan::create([
            'user_id' => User::factory()->create()->id, 'name' => 'Caça', 'mode' => 'laboratory', 'status' => 'running',
            'scope' => ['lab' => true, 'url' => 'http://lab.egide.test:8788/vulneravel',
                'rules' => [['method' => '*', 'path' => '/', 'prefix' => true]], 'denied' => ['/administracao'], 'api' => null],
            'provider' => 'lab', 'budget' => 1000,
        ]);
        $this->hunter = new ScriptedHunter($script);
        $this->fake = new FakeRunScan($scan->id);
        $this->fake->vulnerable = $vulnerable;
        $inventory = [];
        foreach (['perfil' => 'apelido', 'mensagem' => 'nome', 'diagnostico' => 'host', 'busca' => 'q'] as $route => $param) {
            $inventory['GET /servicos/vulneravel/'.$route] = ['method' => 'GET', 'path' => '/servicos/vulneravel/'.$route, 'params' => [$param], 'body' => [], 'auth' => true, 'seen_in' => 'xhr'];
        }
        $reflection = new \ReflectionClass(RunScan::class);
        foreach (['scan' => $scan, 'inventory' => $inventory] as $property => $value) {
            $prop = $reflection->getProperty($property);
            $prop->setAccessible(true);
            $prop->setValue($this->fake, $value);
        }
        $hunt = $reflection->getMethod('hunt');
        $hunt->setAccessible(true);
        $hunt->invoke($this->fake, $this->hunter, ['token' => 'cbteste', 'base' => 'http://coletor.test', 'url' => 'http://coletor.test/api/colaborador/cbteste']);

        return $scan->fresh();
    }

    public function test_ai_bypasses_a_bracket_filter_with_an_attribute_breakout_proved_by_the_oracle(): void
    {
        $scan = $this->hunt([ScriptedHunter::step('xss', '/servicos/vulneravel/perfil', 'apelido', '" autofocus onfocus="{MARKER}')]);

        $finding = $scan->findings()->where('category', 'InjectionCheck · XSS refletido')->sole();
        $this->assertSame('/servicos/vulneravel/perfil', $finding->evidence['path']);
        $this->assertTrue($finding->evidence['hunted']);
        $this->assertSame('teste roteirizado', $finding->evidence['rationale']);
    }

    public function test_ai_proves_template_and_command_injection_by_evaluation(): void
    {
        $scan = $this->hunt([
            ScriptedHunter::step('ssti', '/servicos/vulneravel/mensagem', 'nome', '{{{A}*{B}}}'),
            ScriptedHunter::step('command', '/servicos/vulneravel/diagnostico', 'host', '127.0.0.1;echo $(({A}*{B}))'),
            ScriptedHunter::step('command_time', '/servicos/vulneravel/diagnostico', 'host', '127.0.0.1;sleep 6'),
        ]);
        $categories = $scan->findings()->pluck('category')->all();

        $this->assertContains('InjectionCheck · SSTI', $categories);
        $this->assertSame(1, count(array_keys($categories, 'InjectionCheck · injeção de comando')), 'o mesmo achado não se repete');
    }

    public function test_destructive_or_out_of_scope_ideas_are_blocked_and_explained_to_the_ai(): void
    {
        $scan = $this->hunt([
            ScriptedHunter::step('sqli_error', '/servicos/vulneravel/busca', 'q', "1'; DROP TABLE faturas;-- -"),
            ScriptedHunter::step('xss', '/administracao/usuarios', 'q', '{MARKER}'),
        ]);

        $this->assertSame([], array_filter($this->fake->sent, fn ($sent) => str_contains($sent, 'DROP') || str_contains($sent, 'administracao')));
        $feedback = end($this->hunter->contexts)['experimentos_recentes'];
        $this->assertStringContainsString('destrutiva', $feedback[0]['resultado']);
        $this->assertStringContainsString('escopo', $feedback[1]['resultado']);
        $this->assertSame(0, $scan->findings()->count());
    }

    public function test_ai_experiment_surfaces_a_leaked_stack_trace_as_a_disclosure_finding(): void
    {
        $scan = $this->hunt([ScriptedHunter::step('xss', '/servicos/vulneravel/relatorio', 'mes', '"><b>{MARKER}</b>')]);

        $finding = $scan->findings()->where('category', 'ConfigCheck · rastro de pilha')->sole();
        $this->assertSame('/servicos/vulneravel/relatorio', $finding->evidence['path']);
        $this->assertSame('medium', $finding->severity);
        $this->assertSame('OWASP A05:2021 · CWE-209', $finding->evidence['reference']);
    }

    public function test_fixed_report_does_not_leak_a_stack_trace(): void
    {
        $scan = $this->hunt([ScriptedHunter::step('xss', '/servicos/vulneravel/relatorio', 'mes', '"><b>{MARKER}</b>')], vulnerable: false);

        $this->assertSame(0, $scan->findings()->where('category', 'ConfigCheck · rastro de pilha')->count());
    }

    public function test_ai_sees_the_response_of_each_experiment_to_adapt(): void
    {
        $this->hunt([ScriptedHunter::step('xss', '/servicos/vulneravel/perfil', 'apelido', '"><b>{MARKER}</b>')]);

        $tried = end($this->hunter->contexts)['experimentos_recentes'][0];
        $this->assertSame('protegido', $tried['resultado']);
        $this->assertStringContainsString('value=', $tried['trecho']);
        $this->assertStringNotContainsString('<b>', $tried['trecho']);
    }

    public function test_fixed_variant_resists_the_same_creative_attacks(): void
    {
        $scan = $this->hunt([
            ScriptedHunter::step('xss', '/servicos/vulneravel/perfil', 'apelido', '" autofocus onfocus="{MARKER}'),
            ScriptedHunter::step('ssti', '/servicos/vulneravel/mensagem', 'nome', '{{{A}*{B}}}'),
        ], vulnerable: false);

        $this->assertSame(0, $scan->findings()->count());
    }

    public function test_hunt_stops_when_the_ai_says_it_is_done(): void
    {
        $this->hunt([
            ['done' => true, 'reason' => 'superfície esgotada', 'experiment' => ScriptedHunter::step('xss', '/', 'q', '{MARKER}')['experiment']],
            ScriptedHunter::step('xss', '/servicos/vulneravel/perfil', 'apelido', '{MARKER}'),
        ]);

        $this->assertCount(1, $this->hunter->contexts);
        $this->assertSame([], $this->fake->sent);
    }
}
