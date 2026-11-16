<?php

namespace Tests\Feature;

use App\Models\Finding;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class FindingTrackTest extends TestCase
{
    use RefreshDatabase;

    private function scan(): Scan
    {
        return Scan::create(['user_id' => User::factory()->create()->id, 'name' => 'Lab', 'mode' => 'laboratory', 'scope' => ['lab' => true], 'status' => 'completed']);
    }

    private function finding(Scan $scan, array $attributes = []): Finding
    {
        return $scan->findings()->create(array_merge([
            'title' => 'Leitura de fatura de outra conta',
            'severity' => 'low',
            'category' => 'ApiCheck · BOLA',
            'evidence' => ['path' => '/api/faturas/7'],
            'remediation' => 'Verifique o dono do objeto.',
        ], $attributes));
    }

    public function test_migration_adds_track_and_cvss_columns(): void
    {
        $this->assertTrue(Schema::hasColumns('findings', ['track', 'cvss_vector', 'cvss_score']));
    }

    public function test_finding_with_impact_gets_severity_and_cvss_from_the_rubric(): void
    {
        $finding = $this->finding($this->scan(), [
            'severity' => 'low',
            'evidence' => ['path' => '/api/faturas/7', 'impact' => ['access' => 'leitura', 'reach' => 'entre_contas', 'sensitive' => true]],
        ]);

        $stored = $finding->fresh();
        $this->assertSame('medium', $stored->severity);
        $this->assertSame('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', $stored->cvss_vector);
        $this->assertSame(6.5, $stored->cvss_score);
        $this->assertSame('medium', $finding->severity);
    }

    public function test_rubric_can_raise_a_finding_to_critical(): void
    {
        $finding = $this->finding($this->scan(), [
            'severity' => 'medium',
            'evidence' => ['impact' => ['access' => 'execucao', 'reach' => 'sem_autenticacao']],
        ])->fresh();

        $this->assertSame('critical', $finding->severity);
        $this->assertSame(9.8, $finding->cvss_score);
    }

    public function test_finding_without_impact_keeps_severity_and_gains_a_representative_vector(): void
    {
        $finding = $this->finding($this->scan(), ['severity' => 'high'])->fresh();

        $this->assertSame('high', $finding->severity);
        $this->assertSame('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', $finding->cvss_vector);
        $this->assertSame(7.5, $finding->cvss_score);
    }

    public function test_explicit_vector_without_impact_is_kept(): void
    {
        $finding = $this->finding($this->scan(), [
            'severity' => 'medium',
            'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
            'cvss_score' => 6.1,
        ])->fresh();

        $this->assertSame('medium', $finding->severity);
        $this->assertSame('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', $finding->cvss_vector);
        $this->assertSame(6.1, $finding->cvss_score);
    }

    public function test_unrecognized_impact_never_downgrades_a_proved_finding(): void
    {
        $finding = $this->finding($this->scan(), [
            'severity' => 'high',
            'evidence' => ['impact' => ['access' => 'desconhecido']],
        ])->fresh();

        $this->assertSame('high', $finding->severity);
        $this->assertSame(7.5, $finding->cvss_score);
    }

    public function test_impact_that_is_not_an_array_is_ignored(): void
    {
        $finding = $this->finding($this->scan(), [
            'severity' => 'critical',
            'evidence' => ['impact' => 'alto'],
        ])->fresh();

        $this->assertSame('critical', $finding->severity);
        $this->assertSame(9.8, $finding->cvss_score);
    }

    public function test_track_defaults_to_achado(): void
    {
        $finding = $this->finding($this->scan());

        $this->assertSame('achado', $finding->track);
        $this->assertSame('achado', $finding->fresh()->track);
    }

    public function test_scopes_split_achados_from_observacoes(): void
    {
        $scan = $this->scan();
        $this->finding($scan);
        $this->finding($scan, ['title' => 'Divergência sem marcador', 'track' => 'observacao']);
        $this->finding($scan, ['title' => 'Outro achado']);

        $this->assertSame(2, $scan->findings()->achados()->count());
        $this->assertSame(1, $scan->findings()->observacoes()->count());
        $this->assertSame('Divergência sem marcador', Finding::observacoes()->first()->title);
    }
}
