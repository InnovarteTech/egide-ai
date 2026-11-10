<?php

namespace App\Security;

use App\Models\Scan;

final class AgenticRun
{
    public function __construct(private array $scope) {}

    public static function budget(Scan $scan): array
    {
        $config = (array) config('egide.agentic', []);

        return [
            'max_endpoints' => (int) ($config['max_endpoints'] ?? 12),
            'max_payloads_per_point' => (int) ($config['max_payloads_per_point'] ?? 6),
            'max_escalation_depth' => (int) ($config['max_escalation_depth'] ?? 2),
            'max_strategist_calls' => (int) ($config['max_strategist_calls'] ?? 40),
        ];
    }

    public static function withinBudget(array $spent, array $budget): bool
    {
        foreach ($budget as $dimension => $max) {
            $key = str_starts_with($dimension, 'max_') ? substr($dimension, 4) : $dimension;
            if (is_int($max) && ($spent[$key] ?? 0) >= $max) {
                return false;
            }
        }

        return true;
    }

    public static function destructive(string $route): bool
    {
        $path = explode('?', $route, 2)[0];

        return (bool) preg_match('~(delete|deletar|remove|destroy|destruir|cancel|logout|sair|excluir|apagar|encerrar|revoke|reset|desativar|inativar|bloquear|descadastrar)~i', $path);
    }

    public static function selectTargets(array $inventory, int $maxEndpoints): array
    {
        $scored = [];
        foreach ($inventory as $entry) {
            $path = (string) ($entry['path'] ?? '');
            if ($path === '' || preg_match('~\.(css|js|mjs|png|jpe?g|gif|svg|webp|woff2?|ttf|ico|map)$~i', $path)) {
                continue;
            }
            $score = 0;
            $score += str_contains($path, '/api') ? 2 : 0;
            $score += (! empty($entry['params']) || ! empty($entry['body'])) ? 2 : 0;
            $score += preg_match('~/(\{id\}|\d+)(?=/|$)~', $path) ? 1 : 0;
            $scored[] = ['score' => $score, 'entry' => $entry];
        }
        usort($scored, fn ($a, $b) => $b['score'] <=> $a['score']);

        return array_map(fn ($row) => $row['entry'], array_slice($scored, 0, max(0, $maxEndpoints)));
    }

    public function shouldProbe(string $route): bool
    {
        return Scope::allows($this->scope, 'GET', $route) && ! self::destructive($route);
    }

    public static function authChecks(array $inventory, ?string $token): array
    {
        $checks = [];
        if (is_string($token) && $token !== '') {
            $checks[] = ['check' => 'jwt', 'token' => $token];
        }
        $seen = [];
        foreach ($inventory as $entry) {
            $path = (string) ($entry['path'] ?? '');
            if ($path !== '' && ! isset($seen[$path]) && ! self::destructive($path) && preg_match('~/(auth|login|entrar|session|token|oauth|signin)~i', $path)) {
                $seen[$path] = true;
                $checks[] = ['check' => 'rate', 'path' => $path];
            }
        }

        return $checks;
    }
}
