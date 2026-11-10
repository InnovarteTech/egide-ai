<?php

namespace App\Jobs\Concerns;

use App\Models\CollaboratorHit;
use App\Models\Finding;
use App\Security\PayloadOracles;
use App\Security\Payloads;
use Illuminate\Support\Facades\Storage;
use Throwable;

trait ProbesInjectionPoints
{
    private array $proven = [];

    private array $disclosed = [];

    private function probePoint(array $endpoint, array $point, array $callback, int $maxPayloads = 6): void
    {
        $path = $endpoint['path'];
        $proof = $path.'|'.$point['point'].'|'.($point['key'] ?? '');
        if (! $this->inScope($path) || ($point['class'] === 'sqli_bool' && isset($this->proven[$proof]))) {
            return;
        }
        $booleanBase = [];
        if ($point['class'] === 'sqli_bool') {
            $booleanBase = [$this->sendProbe($path, $point, '1'), $this->sendProbe($path, $point, '1')];
            if (count(array_filter($booleanBase, [PayloadOracles::class, 'usable'])) < 2) {
                $this->cover('InjectionCheck · SQLi booleano', $path, 'nao_testado');

                return;
            }
        }
        foreach (array_slice(Payloads::for($point['class'], $point['point'], ['context' => 'html']), 0, max(1, $maxPayloads)) as $payload) {
            $this->checkStop();
            if (! $this->budgetAllows(4)) {
                return;
            }
            $found = match ($point['class']) {
                'sqli_bool' => $this->booleanProbe($path, $point, $payload, $booleanBase),
                'open_redirect' => $this->redirectProbe($path, $point, $payload),
                'sqli_time' => $this->timeProbe($path, $point, $payload),
                'ssrf' => $this->ssrfProbe($path, $point, $payload, $callback),
                default => $this->responseProbe($path, $point, $payload),
            };
            if ($found) {
                if (in_array($point['class'], ['sqli_time', 'sqli_error', 'sqli_bool'], true)) {
                    $this->proven[$proof] = true;
                }

                return;
            }
        }
    }

    private function timeProbe(string $path, array $point, array $payload): bool
    {
        $base = $this->sendProbe($path, $point, '1');
        $slow = $this->sendProbe($path, $point, $payload['value']);
        $assessment = $this->injectionTimeAssess($path, (float) ($base['elapsed'] ?? 0), (float) ($slow['elapsed'] ?? 0), (int) ($slow['status'] ?? 200));

        return $this->recordAssessment('InjectionCheck · SQLi por tempo', $path, $assessment, 'Atraso controlado indica SQLi',
            "A carga temporal em {$path} ({$point['point']}) atrasou a resposta.");
    }

    private function ssrfProbe(string $path, array $point, array $payload, array $callback): bool
    {
        $token = $callback['token'].sprintf('r%02d', $this->probeIndex++);
        $this->sendProbe($path, $point, str_replace(Payloads::CALLBACK, $callback['base'].'/api/colaborador/'.$token, $payload['value']));
        usleep(800000);
        $hits = CollaboratorHit::where('token', $token)->get()
            ->map(fn ($hit) => ['source_ip' => $hit->source_ip, 'path' => $hit->path, 'received_at' => (string) $hit->received_at])->all();
        $assessment = $this->ssrfAssess($path, $hits, $token);

        return $this->recordAssessment('SSRF · callback out-of-band', $path, $assessment, 'Servidor chamou o coletor da Égide',
            "A injeção em {$path} ({$point['point']}) fez o servidor chamar o callback.");
    }

    private function responseProbe(string $path, array $point, array $payload): bool
    {
        $probe = $this->sendProbe($path, $point, $payload['value']);
        $sample = (string) ($probe['sample'] ?? '');
        if ($this->jwtToken === null && preg_match('~eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}~', $sample, $hit)) {
            $this->jwtToken = $hit[0];
        }
        [$label, $title, $assessment] = match ($point['class']) {
            'sqli_error' => ['InjectionCheck · SQLi por erro', 'Mensagem de erro do banco vazada', PayloadOracles::sqlErrorAssess($path, $sample)],
            'nosql' => ['InjectionCheck · NoSQL', 'Erro de banco NoSQL vazado', PayloadOracles::noSqlAssess($path, $sample)],
            'traversal' => ['InjectionCheck · path traversal', 'Travessia de diretório expôs arquivo do sistema', PayloadOracles::traversalAssess($path, $sample)],
            'graphql' => ['InventoryCheck · GraphQL introspection', 'Introspecção de GraphQL habilitada', PayloadOracles::graphqlAssess($path, $sample)],
            default => ['InjectionCheck · XSS refletido', 'Entrada refletida sem escape', $this->injectionReflectedAssess($payload['value'], $path, $sample, $probe['type'] ?? '')],
        };

        return $this->recordAssessment($label, $path, $assessment, $title, "Verificação {$point['class']} em {$path} ({$point['point']}).",
            $this->evidenceUrl($path, $point, $payload['value']), $point['class'] !== 'graphql');
    }

    private function sendProbe(string $path, array $point, string $value): array
    {
        $probe = $this->runner('/probe', ['path' => $path, 'inject' => ['point' => $point['point'], 'key' => $point['key'], 'value' => $value], 'markers' => []]);
        $seen = $this->observe($this->frameDue());
        $this->noticeDisclosure($path, (string) ($probe['sample'] ?? ''));

        return [...$probe, 'network' => $seen['network'] ?? []];
    }

    private function noticeDisclosure(string $path, string $sample): void
    {
        if (count($this->disclosed) >= 3 || $sample === '') {
            return;
        }
        $assessment = PayloadOracles::stackTraceAssess($path, $sample);
        if (! $assessment['finding']) {
            return;
        }
        $category = $assessment['finding']['category'];
        $key = $category.'|'.$path;
        if (isset($this->disclosed[$key])
            || $this->scan->findings()->where('category', $category)->get()->contains(fn ($known) => ($known->evidence['path'] ?? null) === $path)) {
            return;
        }
        $this->disclosed[$key] = true;
        $this->recordAssessment($category, $path, $assessment, $assessment['finding']['title'],
            'A resposta de '.$path.' vazou um rastro de erro detalhado, observado durante a injeção.');
    }

    private function probeMethod(array $point): string
    {
        return $point['point'] === 'body' ? 'POST' : 'GET';
    }

    private function booleanProbe(string $path, array $point, array $payload, array $base): bool
    {
        $round = fn () => [$this->sendProbe($path, $point, $payload['value']), $this->sendProbe($path, $point, $payload['false'])];
        $rounds = [$round()];
        if (PayloadOracles::booleanRound($payload['value'], $base, $rounds[0]) === 'holds') {
            $rounds[] = $round();
        }
        $assessment = PayloadOracles::booleanSqlAssess($path, $payload['value'], $base, $rounds, $this->probeMethod($point));

        return $this->recordAssessment('InjectionCheck · SQLi booleano', $path, $assessment, 'Condição booleana altera a resposta',
            "A condição falsa em {$path} ({$point['point']}) mudou a resposta de forma consistente.");
    }

    private function redirectProbe(string $path, array $point, array $payload): bool
    {
        $probe = $this->sendProbe($path, $point, $payload['value']);
        $trimmed = rtrim($path, '/');
        $sent = $point['point'] === 'path' && str_contains($trimmed, '/')
            ? substr($trimmed, 0, strrpos($trimmed, '/') + 1).rawurlencode($payload['value']) : '';
        $assessment = PayloadOracles::openRedirectAssess($path, (string) $payload['marker'], $probe['network'], $this->probeMethod($point), $sent);

        return $this->recordAssessment('RedirectCheck · open redirect', $path, $assessment, 'Redirecionamento para domínio externo',
            "O parâmetro {$point['key']} em {$path} redirecionou para o domínio de teste.");
    }

    private function recordAssessment(string $check, string $path, array $assessment, string $title, string $detail, ?string $evidenceUrl = null, bool $capture = false): bool
    {
        $this->cover($check, $path, $assessment['verdict']);
        if (! $assessment['finding']) {
            return false;
        }
        $finding = $this->scan->findings()->create($assessment['finding']);
        $this->scan->event('finding', $title, $detail, $assessment['finding']['evidence']);
        if ($capture) {
            $this->captureEvidence($finding, $evidenceUrl);
        }

        return true;
    }

    private function evidenceUrl(string $path, array $point, string $value): ?string
    {
        if (! str_starts_with($path, '/') || str_starts_with($path, '//') || $point['point'] === 'body') {
            return null;
        }
        if ($point['point'] === 'path') {
            $trimmed = rtrim($path, '/');

            return substr($trimmed, 0, strrpos($trimmed, '/') + 1).rawurlencode($value);
        }
        $key = is_string($point['key'] ?? null) && preg_match('~^[A-Za-z0-9_.\-]{1,40}$~', $point['key']) ? $point['key'] : 'q';

        return $path.(str_contains($path, '?') ? '&' : '?').http_build_query([$key => $value]);
    }

    private function captureEvidence(Finding $finding, ?string $url): void
    {
        try {
            if ($url !== null) {
                $this->runner('/action', ['kind' => 'goto', 'path' => $url]);
                $this->settle();
            }
            $frame = base64_decode((string) ($this->observe(true)['frame'] ?? ''), true);
            if ($frame && strlen($frame) < 600_000 && str_starts_with($frame, "\xff\xd8")) {
                Storage::put('findings/'.$finding->id.'.jpg', $frame);
                $finding->update(['evidence' => [...$finding->evidence, 'screenshot' => true]]);
            }
        } catch (Throwable) {
        }
    }

    protected function settle(): void
    {
        usleep(1500000);
    }
}
