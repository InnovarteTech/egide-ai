<?php

namespace Tests\Unit;

use App\Security\Checks;
use App\Security\Severity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class SeverityTest extends TestCase
{
    public static function knownVectors(): array
    {
        return [
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
            ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3],
            ['CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', 3.1],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N', 8.6],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N', 5.8],
            ['CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 5.4],
            ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', 4.8],
            ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N', 4.9],
            ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
            ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6],
            ['CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 8.8],
            ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0],
        ];
    }

    #[DataProvider('knownVectors')]
    public function test_base_score_follows_the_official_cvss_31_formula(string $vector, float $score): void
    {
        $this->assertSame($score, Severity::score($vector));
    }

    public function test_score_accepts_a_vector_without_the_version_prefix(): void
    {
        $this->assertSame(9.8, Severity::score('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
    }

    public function test_incomplete_or_invalid_vectors_score_zero(): void
    {
        $this->assertSame(0.0, Severity::score('CVSS:3.1/AV:N/AC:L'));
        $this->assertSame(0.0, Severity::score('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
        $this->assertSame(0.0, Severity::score(''));
    }

    public static function rubric(): array
    {
        return [
            'leitura entre contas' => [['access' => 'leitura', 'reach' => 'entre_contas'], 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5, 'medium'],
            'leitura entre contas sem dado sensível' => [['access' => 'leitura', 'reach' => 'entre_contas', 'sensitive' => false], 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', 4.3, 'medium'],
            'leitura sem autenticação' => [['access' => 'leitura', 'reach' => 'sem_autenticacao'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5, 'high'],
            'escrita entre contas' => [['access' => 'escrita', 'reach' => 'entre_contas'], 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N', 7.1, 'high'],
            'exclusão entre contas' => [['access' => 'exclusao', 'reach' => 'entre_contas'], 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H', 8.1, 'high'],
            'execução sem autenticação' => [['access' => 'execucao', 'reach' => 'sem_autenticacao'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'critical'],
            'exposição sem autenticação' => [['access' => 'exposicao', 'reach' => 'sem_autenticacao'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3, 'medium'],
            'exposição sensível' => [['access' => 'exposicao', 'reach' => 'sem_autenticacao', 'sensitive' => true], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5, 'high'],
            'configuração' => [['access' => 'configuracao', 'reach' => 'sem_autenticacao'], 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', 4.8, 'medium'],
            'escrita na mesma conta' => [['access' => 'escrita', 'reach' => 'mesma_conta'], 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', 5.4, 'medium'],
            'leitura pelo servidor (SSRF)' => [['access' => 'leitura', 'reach' => 'servidor'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N', 8.6, 'high'],
            'execução no servidor' => [['access' => 'execucao', 'reach' => 'servidor'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'critical'],
            'exposição no cliente (XSS)' => [['access' => 'exposicao', 'reach' => 'cliente'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N', 4.7, 'medium'],
            'privilégio alto sobrescreve' => [['access' => 'leitura', 'reach' => 'entre_contas', 'privileges' => 'alto'], 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N', 4.9, 'medium'],
            'privilégio nenhum sobrescreve' => [['access' => 'leitura', 'reach' => 'entre_contas', 'privileges' => 'nenhum'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5, 'high'],
            'interação exigida' => [['access' => 'execucao', 'reach' => 'sem_autenticacao', 'interaction' => true], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8, 'high'],
            'configuração com interação vira baixa' => [['access' => 'configuracao', 'reach' => 'sem_autenticacao', 'privileges' => 'alto', 'interaction' => true], 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N', 3.1, 'low'],
        ];
    }

    #[DataProvider('rubric')]
    public function test_rubric_derives_the_cvss_vector_and_severity(array $impact, string $vector, float $score, string $severity): void
    {
        $this->assertSame(['severity' => $severity, 'vector' => $vector, 'score' => $score], Severity::rate($impact));
    }

    public function test_unknown_access_has_no_impact_and_scores_zero(): void
    {
        $rated = Severity::rate(['access' => 'outra_coisa', 'reach' => 'entre_contas']);

        $this->assertSame(0.0, $rated['score']);
        $this->assertSame('low', $rated['severity']);
    }

    public function test_severity_boundaries(): void
    {
        $this->assertSame('critical', Severity::fromScore(9.0));
        $this->assertSame('high', Severity::fromScore(8.9));
        $this->assertSame('high', Severity::fromScore(7.0));
        $this->assertSame('medium', Severity::fromScore(6.9));
        $this->assertSame('medium', Severity::fromScore(4.0));
        $this->assertSame('low', Severity::fromScore(3.9));
        $this->assertSame('low', Severity::fromScore(0.1));
    }

    public function test_representative_vector_matches_the_checks_table_without_changing_severity(): void
    {
        foreach (Checks::CVSS as $severity => $cvss) {
            $rated = Severity::fromSeverity($severity);

            $this->assertSame($severity, $rated['severity']);
            $this->assertSame($cvss['score'], $rated['score']);
            $this->assertSame($cvss['score'], Severity::score($rated['vector']));
            $this->assertSame($severity, Severity::fromScore($rated['score']));
        }
    }

    public function test_unknown_severity_gets_no_invented_vector(): void
    {
        $this->assertSame(['severity' => 'info', 'vector' => null, 'score' => null], Severity::fromSeverity('info'));
    }
}
