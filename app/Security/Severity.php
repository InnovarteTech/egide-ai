<?php

namespace App\Security;

final class Severity
{
    private const WEIGHTS = [
        'AV' => ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2],
        'AC' => ['L' => 0.77, 'H' => 0.44],
        'UI' => ['N' => 0.85, 'R' => 0.62],
        'C' => ['H' => 0.56, 'L' => 0.22, 'N' => 0.0],
        'I' => ['H' => 0.56, 'L' => 0.22, 'N' => 0.0],
        'A' => ['H' => 0.56, 'L' => 0.22, 'N' => 0.0],
    ];

    private const PRIVILEGES = [
        'U' => ['N' => 0.85, 'L' => 0.62, 'H' => 0.27],
        'C' => ['N' => 0.85, 'L' => 0.68, 'H' => 0.5],
    ];

    private const ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

    private const REPRESENTATIVE = [
        'critical' => ['AV' => 'N', 'AC' => 'L', 'PR' => 'N', 'UI' => 'N', 'S' => 'U', 'C' => 'H', 'I' => 'H', 'A' => 'H'],
        'high' => ['AV' => 'N', 'AC' => 'L', 'PR' => 'N', 'UI' => 'N', 'S' => 'U', 'C' => 'H', 'I' => 'N', 'A' => 'N'],
        'medium' => ['AV' => 'N', 'AC' => 'L', 'PR' => 'N', 'UI' => 'N', 'S' => 'U', 'C' => 'L', 'I' => 'N', 'A' => 'N'],
        'low' => ['AV' => 'N', 'AC' => 'H', 'PR' => 'N', 'UI' => 'R', 'S' => 'U', 'C' => 'L', 'I' => 'N', 'A' => 'N'],
    ];

    private const ACCESS = [
        'leitura' => ['C' => 'H'],
        'escrita' => ['C' => 'L', 'I' => 'H'],
        'exclusao' => ['I' => 'H', 'A' => 'H'],
        'execucao' => ['C' => 'H', 'I' => 'H', 'A' => 'H'],
        'exposicao' => ['C' => 'L'],
        'configuracao' => ['AC' => 'H', 'C' => 'L', 'I' => 'L'],
    ];

    private const REACH = [
        'entre_contas' => ['AV' => 'N', 'PR' => 'L', 'S' => 'U'],
        'sem_autenticacao' => ['AV' => 'N', 'PR' => 'N'],
        'mesma_conta' => ['PR' => 'L'],
        'servidor' => ['AV' => 'N', 'PR' => 'N', 'S' => 'C'],
        'cliente' => ['UI' => 'R', 'S' => 'C'],
    ];

    private const PRIVILEGE_LEVELS = ['nenhum' => 'N', 'baixo' => 'L', 'alto' => 'H'];

    public static function rate(array $impact): array
    {
        $metrics = ['AV' => 'N', 'AC' => 'L', 'PR' => 'N', 'UI' => 'N', 'S' => 'U', 'C' => 'N', 'I' => 'N', 'A' => 'N'];
        $access = self::text($impact['access'] ?? null);
        $reach = self::text($impact['reach'] ?? null);
        $privilege = self::text($impact['privileges'] ?? null);
        $sensitive = $impact['sensitive'] ?? null;

        $metrics = array_merge($metrics, self::ACCESS[$access] ?? []);
        if ($access === 'leitura' && $sensitive === false) {
            $metrics['C'] = 'L';
        }
        if ($access === 'exposicao' && $sensitive === true) {
            $metrics['C'] = 'H';
        }

        $metrics = array_merge($metrics, self::REACH[$reach] ?? []);
        if ($reach === 'mesma_conta') {
            foreach (['C', 'I'] as $metric) {
                $metrics[$metric] = $metrics[$metric] === 'H' ? 'L' : $metrics[$metric];
            }
        }

        if (isset(self::PRIVILEGE_LEVELS[$privilege])) {
            $metrics['PR'] = self::PRIVILEGE_LEVELS[$privilege];
        }
        if (($impact['interaction'] ?? null) === true) {
            $metrics['UI'] = 'R';
        }

        $score = self::compute($metrics);

        return ['severity' => self::fromScore($score), 'vector' => self::vector($metrics), 'score' => $score];
    }

    public static function fromSeverity(string $severity): array
    {
        $metrics = self::REPRESENTATIVE[$severity] ?? null;
        if ($metrics === null) {
            return ['severity' => $severity, 'vector' => null, 'score' => null];
        }

        return ['severity' => $severity, 'vector' => self::vector($metrics), 'score' => self::compute($metrics)];
    }

    public static function fromScore(float $score): string
    {
        return match (true) {
            $score >= 9.0 => 'critical',
            $score >= 7.0 => 'high',
            $score >= 4.0 => 'medium',
            default => 'low',
        };
    }

    public static function score(string $vector): float
    {
        $metrics = [];
        foreach (explode('/', $vector) as $part) {
            [$name, $value] = array_pad(explode(':', $part, 2), 2, null);
            if ($name !== 'CVSS') {
                $metrics[$name] = $value;
            }
        }

        foreach (self::ORDER as $name) {
            if (! isset($metrics[$name])) {
                return 0.0;
            }
        }

        return self::compute($metrics);
    }

    private static function compute(array $metrics): float
    {
        $changed = ($metrics['S'] ?? null) === 'C';
        if (! in_array($metrics['S'] ?? null, ['U', 'C'], true)) {
            return 0.0;
        }

        $weights = [];
        foreach (self::WEIGHTS as $name => $table) {
            if (! isset($table[$metrics[$name]])) {
                return 0.0;
            }
            $weights[$name] = $table[$metrics[$name]];
        }
        $privileges = self::PRIVILEGES[$changed ? 'C' : 'U'][$metrics['PR']] ?? null;
        if ($privileges === null) {
            return 0.0;
        }

        $iss = 1 - ((1 - $weights['C']) * (1 - $weights['I']) * (1 - $weights['A']));
        $impact = $changed ? 7.52 * ($iss - 0.029) - 3.25 * (($iss - 0.02) ** 15) : 6.42 * $iss;
        if ($impact <= 0) {
            return 0.0;
        }

        $exploitability = 8.22 * $weights['AV'] * $weights['AC'] * $privileges * $weights['UI'];
        $base = $changed ? 1.08 * ($impact + $exploitability) : $impact + $exploitability;

        return self::roundUp(min($base, 10.0));
    }

    private static function roundUp(float $value): float
    {
        $integer = (int) round($value * 100000);

        return $integer % 10000 === 0 ? $integer / 100000 : (floor($integer / 10000) + 1) / 10;
    }

    private static function text(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }

    private static function vector(array $metrics): string
    {
        $parts = ['CVSS:3.1'];
        foreach (self::ORDER as $name) {
            $parts[] = $name.':'.$metrics[$name];
        }

        return implode('/', $parts);
    }
}
