<?php

namespace Tests\Feature;

use App\Models\ApiToken;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class CiGateTest extends TestCase
{
    use RefreshDatabase;

    public function test_ci_gate_blocks_on_critical_or_high(): void
    {
        $user = User::factory()->create();
        $plain = ApiToken::issue();
        ApiToken::create(['user_id' => $user->id, 'token_hash' => ApiToken::hash($plain), 'prefix' => substr($plain, 0, 14), 'name' => 'ci']);

        $clean = Scan::create(['user_id' => $user->id, 'name' => 'Limpa', 'mode' => 'laboratory', 'scope' => ['lab' => true], 'status' => 'completed', 'result' => 'protected']);
        $cleanGate = $this->withToken($plain)->getJson('/api/v1/sessoes/'.$clean->id)->assertOk()->json('portao');
        $this->assertTrue($cleanGate['passou']);
        $this->assertFalse($cleanGate['pendente']);

        $risky = Scan::create(['user_id' => $user->id, 'name' => 'Risco', 'mode' => 'laboratory', 'scope' => ['lab' => true], 'status' => 'completed', 'result' => 'exposure']);
        $risky->findings()->create(['title' => 'BOLA', 'severity' => 'critical', 'category' => 'x', 'evidence' => [], 'remediation' => 'y']);
        $response = $this->withToken($plain)->getJson('/api/v1/sessoes/'.$risky->id)->assertOk();
        $this->assertFalse($response->json('portao.passou'));
        $this->assertSame('achados_bloqueantes', $response->json('portao.motivo'));
        $this->assertSame(9.8, $response->json('cvss_estimado'));

        $running = Scan::create(['user_id' => $user->id, 'name' => 'Rodando', 'mode' => 'laboratory', 'scope' => ['lab' => true], 'status' => 'running']);
        $this->assertFalse($this->withToken($plain)->getJson('/api/v1/sessoes/'.$running->id)->json('portao.passou'));

        // A FAILED scan has zero findings — it must NOT unblock the pipeline (fail closed).
        $failed = Scan::create(['user_id' => $user->id, 'name' => 'Falhou', 'mode' => 'laboratory', 'scope' => ['lab' => true], 'status' => 'failed', 'error' => 'executor caiu']);
        $failedGate = $this->withToken($plain)->getJson('/api/v1/sessoes/'.$failed->id)->assertOk()->json('portao');
        $this->assertFalse($failedGate['passou']);
        $this->assertNotNull($failedGate['motivo']);
    }

    public function test_ci_gate_counts_only_findings_and_lists_observations_apart_with_cvss(): void
    {
        $user = User::factory()->create();
        $plain = ApiToken::issue();
        ApiToken::create(['user_id' => $user->id, 'token_hash' => ApiToken::hash($plain), 'prefix' => substr($plain, 0, 14), 'name' => 'ci']);

        $scan = Scan::create(['user_id' => $user->id, 'name' => 'Observada', 'mode' => 'laboratory', 'scope' => ['lab' => true], 'status' => 'completed', 'result' => 'protected']);
        $scan->findings()->create(['title' => 'Indício de BOLA', 'severity' => 'critical', 'track' => 'observacao', 'category' => 'x', 'evidence' => ['method' => 'GET', 'path' => '/pedidos/2'], 'remediation' => 'y']);
        $scan->findings()->create(['title' => 'Leitura entre contas', 'severity' => 'low', 'category' => 'BOLA', 'remediation' => 'y',
            'evidence' => ['method' => 'GET', 'path' => '/faturas/7', 'impact' => ['access' => 'leitura', 'reach' => 'entre_contas', 'sensitive' => true]]]);

        $response = $this->withToken($plain)->getJson('/api/v1/sessoes/'.$scan->id)->assertOk();

        $this->assertTrue($response->json('portao.passou'));
        $this->assertNull($response->json('portao.motivo'));
        $this->assertSame(['critical' => 0, 'high' => 0, 'medium' => 1, 'low' => 0], $response->json('achados'));
        $this->assertSame(6.5, $response->json('cvss_estimado'));
        $this->assertCount(1, $response->json('itens'));
        $this->assertSame(['Leitura entre contas', 'medium', 'GET /faturas/7', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5], [
            $response->json('itens.0.titulo'), $response->json('itens.0.severidade'), $response->json('itens.0.rota'),
            $response->json('itens.0.cvss_vector'), $response->json('itens.0.cvss_score'),
        ]);
        $this->assertCount(1, $response->json('observacoes'));
        $this->assertSame(['Indício de BOLA', 'critical', 9.8], [
            $response->json('observacoes.0.titulo'), $response->json('observacoes.0.severidade'), $response->json('observacoes.0.cvss_score'),
        ]);
    }
}
