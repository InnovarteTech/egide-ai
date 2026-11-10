<?php

namespace App\Jobs\Concerns;

use App\Security\ApiOracles;
use App\Security\Scope;
use Illuminate\Support\Str;

trait ProbesApiWrites
{
    private function graphqlBatchTest(string $path): void
    {
        if (! Scope::allows($this->scan->scope, 'POST', $path) || ! $this->budgetAllows(2)) {
            return;
        }
        $count = 30;
        $probe = $this->runner('/probe', ['path' => $path, 'method' => 'POST', 'raw_body' => ['query' => ApiOracles::aliasFlood('faturas', '', $count)], 'markers' => []]);
        $this->observe($this->frameDue());
        $sample = (string) ($probe['sample'] ?? '');
        $data = json_decode($sample, true);
        $executed = is_array($data['data'] ?? null)
            ? count(array_filter(array_keys($data['data']), fn ($key) => preg_match('~^egideAlias\d+$~', (string) $key)))
            : 0;
        $this->scan->event('test', 'GraphQL batching · diagnóstico', 'status='.(int) ($probe['status'] ?? 0).' size='.strlen($sample).' type='.($probe['type'] ?? '').' exec='.$executed.' amostra='.Str::limit($sample, 140));
        $assessment = ApiOracles::graphqlBatchingAssess($path, $count, $executed);
        $this->cover('InventoryCheck · GraphQL batching', $path, $assessment['verdict']);
        if ($assessment['finding']) {
            $this->scan->findings()->create($assessment['finding']);
            $this->scan->event('finding', 'GraphQL executa lote de operações', $executed.' operações rodaram numa requisição só em '.$path.'.', $assessment['finding']['evidence']);
        }
    }

    private function prototypePollutionTest(string $writePath, string $readPath): void
    {
        if (! $this->aggressiveAllowed() || ! $this->inScope($writePath) || ! $this->inScope($readPath) || ! $this->budgetAllows(2)) {
            return;
        }
        $marker = 'egidePP'.bin2hex(random_bytes(4));
        $this->runner('/probe', ['path' => $writePath, 'method' => 'POST', 'raw_body' => ['__proto__' => ['egidePoluido' => $marker]], 'markers' => []]);
        $this->observe(false);
        $probe = $this->runner('/probe', ['path' => $readPath, 'markers' => [$marker]]);
        $this->observe(false);
        $assessment = ApiOracles::prototypePollutionAssess($writePath, $marker, (string) ($probe['sample'] ?? ''));
        $this->cover('InjectionCheck · prototype pollution', $writePath, $assessment['verdict']);
        if ($assessment['finding']) {
            $this->scan->findings()->create($assessment['finding']);
            $this->scan->event('finding', 'Prototype pollution confirmada', 'Propriedade injetada via __proto__ contaminou a resposta de '.$readPath.'.', $assessment['finding']['evidence']);
        }
    }

    private function verbMatrixTest(string $path): void
    {
        if (! $this->aggressiveAllowed()) {
            return;
        }
        foreach (['DELETE', 'PUT', 'PATCH'] as $method) {
            if (! $this->budgetAllows(1) || ! Scope::allows($this->scan->scope, $method, $path)) {
                continue;
            }
            $probe = $this->runner('/probe', ['path' => $path, 'method' => $method, 'anon' => true, 'markers' => []]);
            $this->observe(false);
            $assessment = ApiOracles::unauthorizedWriteAssess($path, $method, (int) ($probe['status'] ?? 0));
            $this->cover('AuthCheck · método de escrita sem sessão', $path, $assessment['verdict']);
            if ($assessment['finding']) {
                $this->scan->findings()->create($assessment['finding']);
                $this->scan->event('finding', 'Escrita sem autenticação aceita', $method.' anônimo aceito em '.$path.'.', $assessment['finding']['evidence']);

                return;
            }
        }
    }

    private function raceTest(string $path): void
    {
        if (! $this->aggressiveAllowed() || ! Scope::allows($this->scan->scope, 'POST', $path) || ! $this->budgetAllows(6)) {
            return;
        }
        $result = $this->runner('/race', ['path' => $path, 'method' => 'POST', 'count' => 5, 'body' => ['token' => 'egideRC'.bin2hex(random_bytes(4))]]);
        $this->observe(false);
        $ok = (int) ($result['ok'] ?? 0);
        $assessment = ApiOracles::raceAssess($path, $ok);
        $this->cover('LogicCheck · race condition (TOCTOU)', $path, $assessment['verdict']);
        if ($assessment['finding']) {
            $this->scan->findings()->create($assessment['finding']);
            $this->scan->event('finding', 'Race condition confirmada', $ok.' de 5 requisições paralelas aceitas em '.$path.'.', $assessment['finding']['evidence']);
        }
    }
}
