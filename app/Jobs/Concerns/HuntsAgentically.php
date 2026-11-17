<?php

namespace App\Jobs\Concerns;

use App\Models\Workspace;
use App\Security\AgenticRun;
use App\Security\Hunter;
use App\Security\PayloadOracles;
use App\Security\Planner;
use App\Security\Scope;
use Illuminate\Support\Str;
use Throwable;

trait HuntsAgentically
{
    private const HUNT_LABELS = [
        'xss' => ['InjectionCheck · XSS refletido', 'Entrada refletida sem escape'],
        'sqli_error' => ['InjectionCheck · SQLi por erro', 'Mensagem de erro do banco vazada'],
        'sqli_time' => ['InjectionCheck · SQLi por tempo', 'Atraso controlado indica SQLi'],
        'nosql' => ['InjectionCheck · NoSQL', 'Erro de banco NoSQL vazado'],
        'traversal' => ['InjectionCheck · path traversal', 'Travessia de diretório expôs arquivo do sistema'],
        'graphql' => ['InventoryCheck · GraphQL introspection', 'Introspecção de GraphQL habilitada'],
        'ssti' => ['InjectionCheck · SSTI', 'Template avaliou a expressão injetada'],
        'command' => ['InjectionCheck · injeção de comando', 'Shell avaliou o comando injetado'],
        'command_time' => ['InjectionCheck · injeção de comando', 'Comando injetado atrasou a resposta'],
    ];

    protected function hunter(Planner $planner): Hunter
    {
        return new Hunter($planner);
    }

    private function huntLimit(): int
    {
        $demo = (bool) Workspace::where('user_id', $this->scan->user_id)->value('demo');

        return (int) config($demo ? 'egide.hunt.demo_max_steps' : 'egide.hunt.max_steps', 20);
    }

    private function hunt(Hunter $hunter, array $callback): void
    {
        $limit = $this->huntLimit();
        if (! $this->aggressiveAllowed() || $limit <= 0) {
            return;
        }
        $this->scan->update(['phase' => 'Caça agêntica (IA criativa)']);
        $this->scan->event('test', 'Caça agêntica iniciada', 'A IA propõe experimentos livres dentro do escopo; só entra no relatório o que o oráculo provar.');
        $history = [];
        for ($step = 0; $step < $limit; $step++) {
            $this->checkStop();
            if (! $this->budgetAllows(6)) {
                return;
            }
            try {
                $decision = $hunter->next($this->scan, $this->huntContext($history, $limit - $step));
            } catch (Throwable) {
                $this->scan->event('test', 'Caça agêntica encerrada', 'O motor de IA não respondeu; a caça parou aqui.');

                return;
            }
            if (! empty($decision['done'])) {
                $this->scan->event('test', 'IA encerrou a caça', Str::limit((string) ($decision['reason'] ?? ''), 300));

                return;
            }
            $experiment = (array) ($decision['experiment'] ?? []);
            $summary = ['tecnica' => $experiment['technique'] ?? null, 'rota' => $experiment['path'] ?? null,
                'parametro' => $experiment['key'] ?? null, 'carga' => Str::limit((string) ($experiment['payload'] ?? ''), 160)];
            $method = ($experiment['point'] ?? '') === 'body' ? 'POST' : 'GET';
            $reason = Hunter::guard($experiment, fn (string $path) => Scope::allows($this->scan->scope, $method, $path) && ! AgenticRun::destructive($path));
            if ($reason !== null) {
                $history[] = [...$summary, 'resultado' => 'rejeitado pela trava: '.$reason];
                $this->scan->event('test', 'Experimento da IA barrado pela trava', $reason, $summary);

                continue;
            }
            $this->scan->event('browser', 'Experimento criativo da IA', $summary['tecnica'].' · '.$summary['rota'].' · '.Str::limit((string) ($experiment['rationale'] ?? ''), 160), $summary);
            $history[] = [...$summary, ...$this->runExperiment(Hunter::resolve($experiment), $callback)];
        }
    }

    private function runExperiment(array $x, array $callback): array
    {
        $path = (string) $x['path'];
        $point = ['point' => $x['point'], 'key' => $x['key'] ?? null];
        $method = $this->probeMethod($point);
        $technique = $x['technique'];
        if (in_array($technique, ['sqli_bool', 'ssrf', 'open_redirect'], true)) {
            $before = count($this->coverage);
            match ($technique) {
                'sqli_bool' => $this->booleanProbe($path, $point, ['value' => $x['value'], 'false' => $x['false']], [$this->sendProbe($path, $point, '1'), $this->sendProbe($path, $point, '1')]),
                'ssrf' => $this->ssrfProbe($path, $point, ['value' => $x['value']], $callback),
                default => $this->redirectProbe($path, $point, ['value' => $x['value'], 'marker' => $x['marker']]),
            };
            if ($technique === 'ssrf') {
                $this->cloudSsrfProbe($path, $point);
            }

            return ['resultado' => count($this->coverage) > $before ? end($this->coverage)['verdict'] : 'nao_testado'];
        }
        if (in_array($technique, ['sqli_time', 'command_time'], true)) {
            $base = $this->sendProbe($path, $point, '1');
            $probe = $this->sendProbe($path, $point, $x['value']);
            $assessment = PayloadOracles::delayAssess($path, $technique, (float) ($base['elapsed'] ?? 0), (float) ($probe['elapsed'] ?? 0), (int) ($probe['status'] ?? 0), $method);
        } elseif (in_array($technique, ['ssti', 'command'], true)) {
            $base = $this->sendProbe($path, $point, 'egide');
            $probe = $this->sendProbe($path, $point, $x['value']);
            $assessment = PayloadOracles::evaluationAssess($path, $technique, $x['expected'], (string) ($probe['sample'] ?? ''), (string) ($base['sample'] ?? ''), $method);
        } else {
            $probe = $this->sendProbe($path, $point, $x['value']);
            $sample = (string) ($probe['sample'] ?? '');
            $assessment = match ($technique) {
                'sqli_error' => PayloadOracles::sqlErrorAssess($path, $sample),
                'nosql' => PayloadOracles::noSqlAssess($path, $sample),
                'traversal' => PayloadOracles::traversalAssess($path, $sample),
                'graphql' => PayloadOracles::graphqlAssess($path, $sample),
                default => $this->injectionReflectedAssess($x['value'], $path, $sample, (string) ($probe['type'] ?? '')),
            };
        }

        return [
            'resultado' => $this->recordHunt($technique, $path, $assessment, $x),
            'status' => (int) ($probe['status'] ?? 0),
            'tamanho' => (int) ($probe['size'] ?? strlen((string) ($probe['sample'] ?? ''))),
            'trecho' => $this->huntSnippet((string) ($probe['sample'] ?? ''), [$x['marker'] ?? '', $x['expected'] ?? '']),
        ];
    }

    private function recordHunt(string $technique, string $path, array $assessment, array $x): string
    {
        [$label, $title] = self::HUNT_LABELS[$technique];
        $finding = $assessment['finding'];
        if ($finding && $this->scan->findings()->where('category', $finding['category'])->get()->contains(fn ($known) => ($known->evidence['path'] ?? null) === $path)) {
            $this->cover($label, $path, $assessment['verdict']);

            return 'falha (já provada antes)';
        }
        if ($finding) {
            $assessment['finding']['evidence'] += ['payload' => Str::limit((string) $x['value'], 200)];
            $assessment['finding']['evidence']['hunted'] = true;
            $assessment['finding']['evidence']['rationale'] = Str::limit((string) ($x['rationale'] ?? ''), 240);
        }
        $point = ['point' => $x['point'], 'key' => $x['key'] ?? null];
        $this->recordAssessment($label, $path, $assessment, $title, 'Experimento criativo da IA em '.$path.' confirmado pelo oráculo.',
            $this->evidenceUrl($path, $point, (string) $x['value']), in_array($technique, ['xss', 'sqli_error', 'nosql', 'traversal', 'ssti', 'command'], true));

        return $assessment['verdict'];
    }

    private function huntContext(array $history, int $stepsLeft): array
    {
        $coverage = [];
        foreach ($this->coverage as $row) {
            $coverage[$row['check'].' · '.$row['route']] = $row['verdict'];
        }

        return [
            'inventario' => array_slice(array_values(array_map(fn ($endpoint) => [
                'method' => $endpoint['method'] ?? 'GET', 'path' => $endpoint['path'] ?? '/',
                'params' => $endpoint['params'] ?? [], 'body' => $endpoint['body'] ?? [],
            ], $this->inventory)), 0, 40),
            'cobertura' => array_slice(array_map(fn ($key, $verdict) => $key.' = '.$verdict, array_keys($coverage), $coverage), -60),
            'achados_provados' => $this->scan->findings()->get(['category', 'evidence'])->map(fn ($finding) => $finding->category.' · '.($finding->evidence['path'] ?? ''))->all(),
            'experimentos_recentes' => array_slice($history, -12),
            'passos_restantes' => $stepsLeft,
            'requisicoes_restantes' => max(0, (int) $this->scan->budget - $this->allowed),
        ];
    }

    private function huntSnippet(string $sample, array $needles): string
    {
        $clean = preg_replace(['~eyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]{6,}~', '~\b[A-Fa-f0-9]{32,}\b~', '~[\w.+-]+@[\w-]+\.[\w.-]+~'], ['[token]', '[hex]', '[email]'], $sample);
        foreach (array_filter($needles) as $needle) {
            $at = stripos($clean, (string) $needle);
            if ($at !== false) {
                return Str::limit(substr($clean, max(0, $at - 120), 260), 260);
            }
        }

        return Str::limit($clean, 240);
    }
}
