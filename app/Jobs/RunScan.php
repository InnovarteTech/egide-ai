<?php

namespace App\Jobs;

use App\Jobs\Concerns\HuntsAgentically;
use App\Jobs\Concerns\ProbesApiWrites;
use App\Jobs\Concerns\ProbesInjectionPoints;
use App\Models\CollaboratorHit;
use App\Models\Scan;
use App\Models\Workspace;
use App\Security\AgenticRun;
use App\Security\AttackPoints;
use App\Security\BudgetLedger;
use App\Security\Checks;
use App\Security\ClientScan;
use App\Security\EndpointMap;
use App\Security\PayloadOracles;
use App\Security\Payloads;
use App\Security\Planner;
use App\Security\Scope;
use App\Security\SurfaceImport;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;

class RunScan implements ShouldQueue
{
    use HuntsAgentically, ProbesApiWrites, ProbesInjectionPoints, Queueable;

    public int $timeout = 840;

    public int $tries = 0;

    private ?string $runnerUrl = null;

    private Scan $scan;

    private array $endpoints = [];

    private array $inventory = [];

    private int $probeIndex = 0;

    private ?string $jwtToken = null;

    private int $allowed = 0;

    private int $blocked = 0;

    private array $issues = [];

    private array $coverage = [];

    private float $startedAt = 0;

    private float $lastFrameAt = 0;

    private bool $reserveNoticed = false;

    private int $navigationCost = 10;

    private ?BudgetLedger $ledger = null;

    private array $phaseNoticed = [];

    private ?string $halted = null;

    private const CONFIGURATION_RESERVE = 22;

    private const HUNT_STEP_COST = 8;

    private const CROSS_PROOF_COST = 60;

    public function __construct(public string $scanId)
    {
        $this->timeout = max(10, (int) config('egide.session_minutes', 130)) * 60;
    }

    public function retryUntil(): \DateTimeInterface
    {
        return now()->addMinutes(45);
    }

    private function aggressiveAllowed(): bool
    {
        return ($this->scan->scope['lab'] ?? false) || ($this->scan->scope['env_type'] ?? null) === 'test';
    }

    private function destructiveRoute(string $route): bool
    {
        return AgenticRun::destructive($route);
    }

    private function domProbePoint(string $path, string $point, ?string $key, string $token): bool
    {
        if (! $this->inScope($path)) {
            return false;
        }
        foreach (Payloads::for('dom_xss', $point, ['token' => $token]) as $payload) {
            $this->checkStop();
            if (! $this->budgetAllows($this->navigationCost)) {
                return false;
            }
            $before = $this->allowed;
            $probe = $this->runner('/dom_probe', ['path' => $path, 'point' => $point, 'key' => $key, 'value' => $payload['value'], 'token' => $token]);
            $this->observe($this->frameDue());
            $this->navigationCost = max($this->navigationCost, $this->allowed - $before);
            $assessment = PayloadOracles::domXssAssess($token, $probe);
            $this->cover('InjectionCheck · DOM XSS', $path.($point === 'hash' ? '#' : '?'.$key), $assessment['verdict']);
            if ($assessment['finding']) {
                $assessment['finding']['evidence']['path'] = $path;
                $assessment['finding']['evidence']['source'] = $point === 'hash' ? 'location.hash' : $key;
                $this->captureEvidence($this->scan->findings()->create($assessment['finding']), null);
                $this->scan->event('finding', 'XSS no DOM confirmado no navegador', "A carga em {$path} ({$point}) executou script no DOM.", $assessment['finding']['evidence']);

                return true;
            }
        }

        return false;
    }

    private function domXssSweep(): void
    {
        if (! $this->aggressiveAllowed() || ! $this->budgetAllows(1)) {
            return;
        }
        $entry = parse_url($this->scan->scope['url'], PHP_URL_PATH) ?: '/';
        $this->scan->update(['phase' => 'DOM XSS (análise client-side)']);
        $page = $this->runner('/probe', ['path' => $entry, 'markers' => []]);
        $this->observe(false);
        $js = (string) ($page['sample'] ?? '');
        preg_match_all('~<script[^>]+src=["\']([^"\']+)["\']~i', $js, $scripts);
        foreach (array_slice($scripts[1] ?? [], 0, 3) as $src) {
            $this->checkStop();
            $srcPath = str_starts_with($src, 'http') ? $src : '/'.ltrim($src, '/');
            if (! $this->inScope($srcPath) || ! $this->budgetAllows(1)) {
                continue;
            }
            $bundle = $this->runner('/probe', ['path' => $srcPath, 'markers' => []]);
            $this->observe(false);
            $js .= "\n".((string) ($bundle['sample'] ?? ''));
        }
        $this->absorbBundleRoutes($js);
        $sinks = ClientScan::sinks($js);
        $sourced = array_values(array_filter($sinks, fn ($sink) => $sink['source']));
        $this->cover('ClientScan · sinks DOM', $entry, $sinks ? 'nao_testado' : 'protegido');
        $this->scan->event('test', 'Análise client-side de sinks', count($sinks).' sink(s) perigoso(s) no bundle, '.count($sourced).' com fonte controlável. A confirmação de execução no DOM é que decide o achado.');

        $found = false;
        $token = strtoupper(bin2hex(random_bytes(5)));
        $this->softCheck('DOM XSS hash', function () use (&$found, $entry, $token) {
            $found = $this->domProbePoint($entry, 'hash', null, $token);
        });
        if ($found || ! ClientScan::readsQuery($js)) {
            return;
        }
        $params = [];
        foreach ($this->inventory as $endpoint) {
            foreach ($endpoint['params'] ?? [] as $param) {
                $params[$param] = true;
            }
        }
        foreach (array_slice(array_keys($params), 0, 3) as $param) {
            $this->softCheck('DOM XSS query', function () use (&$found, $entry, $param) {
                $found = $this->domProbePoint($entry, 'query', $param, strtoupper(bin2hex(random_bytes(5))));
            });
            if ($found) {
                return;
            }
        }
    }

    private function absorbBundleRoutes(string $js): void
    {
        $before = count($this->inventory);
        foreach (array_slice(EndpointMap::fromBundle($js, (string) $this->scan->scope['url']), 0, 14) as $route) {
            if ($this->inScope($route)) {
                $this->inventory = EndpointMap::merge($this->inventory, ['method' => 'GET', 'path' => $route, 'auth' => true, 'seen_in' => 'bundle']);
            }
        }
        if (($added = count($this->inventory) - $before) > 0) {
            $this->scan->event('test', 'Rotas de API extraídas do bundle', $added.' rota(s) inferida(s) do JavaScript entraram no mapa para uma exploração mais profunda da conta autenticada.');
        }
    }

    private function agenticBattery(Planner $planner): void
    {
        if (! $this->aggressiveAllowed()) {
            return;
        }
        $run = new AgenticRun($this->scan->scope);
        $budget = AgenticRun::budget($this->scan);
        $spent = ['endpoints' => 0, 'strategist_calls' => 0];
        $callback = $this->callbackToken();
        $this->beginPhase('probers');
        $this->scan->update(['phase' => 'Varredura agêntica']);
        $this->scan->event('test', 'Varredura agêntica de vulnerabilidades', 'A IA planeja e injeta ataques adaptados por endpoint; cada achado é confirmado por oráculo determinístico.');
        $this->softCheck('DOM XSS (client-side)', fn () => $this->domXssSweep());
        $this->scan->update(['phase' => 'Varredura agêntica']);
        foreach (AgenticRun::selectTargets($this->inventory, $budget['max_endpoints']) as $endpoint) {
            $this->checkStop();
            if (! AgenticRun::withinBudget($spent, $budget)) {
                break;
            }
            if (! $run->shouldProbe($endpoint['path'])) {
                continue;
            }
            $spent['endpoints']++;
            $plan = $planner->attackPlan($this->scan, $endpoint);
            $spent['strategist_calls']++;
            foreach ($plan as $point) {
                if (! in_array($point['class'], AttackPoints::INJECTED, true)) {
                    continue;
                }
                if (! $this->budgetAllows(10)) {
                    break 2;
                }
                $this->softCheck('Varredura '.$point['class'].' '.$point['point'], fn () => $this->probePoint($endpoint, $point, $callback, $budget['max_payloads_per_point']));
            }
        }
        foreach ($this->inventory as $endpoint) {
            if (($endpoint['method'] ?? '') === 'POST' && preg_match('~/graphql/?$~i', (string) ($endpoint['path'] ?? ''))) {
                $this->softCheck('GraphQL batching', fn () => $this->graphqlBatchTest($endpoint['path']));
            }
        }
        $this->authBattery();
        if ($this->hunts()) {
            $this->beginPhase('caca');
        }
        $this->softCheck('Caça agêntica', fn () => $this->hunt($this->hunter($planner), $callback));
    }

    private function authBattery(): void
    {
        foreach (AgenticRun::authChecks($this->inventory, $this->jwtToken) as $check) {
            $this->checkStop();
            if ($check['check'] === 'jwt') {
                $this->softCheck('JWT', function () use ($check) {
                    $assessment = $this->jwtAssess($check['token']);
                    $this->cover('AuthCheck · JWT fraco', '(token de sessão)', $assessment['verdict']);
                    if ($assessment['finding']) {
                        $this->scan->findings()->create($assessment['finding']);
                        $this->scan->event('finding', $assessment['finding']['title'], 'Token JWT observado com fraqueza.', $assessment['finding']['evidence']);
                    }
                });

                continue;
            }
            $this->softCheck('Limite de login', function () use ($check) {
                if (! $this->inScope($check['path']) || ! $this->budgetAllows(8)) {
                    return;
                }
                $statuses = [];
                for ($i = 0; $i < 8; $i++) {
                    $this->checkStop();
                    $probe = $this->runner('/probe', ['path' => $check['path'], 'markers' => []]);
                    $this->observe();
                    $statuses[] = (int) ($probe['status'] ?? 0);
                }
                $assessment = $this->authRateAssess($check['path'], $statuses);
                if ($assessment['verdict'] === 'falha') {
                    $assessment = ['verdict' => 'nao_testado', 'finding' => null];
                    $this->scan->event('test', 'Limite de login não confirmado', "A sonda GET em {$check['path']} não dispara tentativa real de login; confirmar limite exige envio de credenciais (POST).");
                }
                $this->cover('AuthCheck · sem limite de tentativas', $check['path'], $assessment['verdict']);
                if ($assessment['finding']) {
                    $this->scan->findings()->create($assessment['finding']);
                    $this->scan->event('finding', 'Login sem limite de tentativas', "A rota {$check['path']} aceitou várias tentativas sem bloquear.", $assessment['finding']['evidence']);
                }
            });
        }
    }

    private function frameDue(): bool
    {
        return microtime(true) - $this->lastFrameAt >= 10;
    }

    private function budgetAllows(int $cost): bool
    {
        $inTime = $this->startedAt <= 0 || microtime(true) - $this->startedAt < $this->timeout - 180;
        if ($inTime && (int) $this->scan->budget - $this->allowed - $cost >= self::CONFIGURATION_RESERVE) {
            return $this->phaseAllows($cost);
        }
        if (! $this->reserveNoticed) {
            $this->reserveNoticed = true;
            $this->scan->event('test', 'Orçamento reservado para a verificação de configuração',
                'As verificações ativas restantes foram puladas para garantir as sondas de arquivos sensíveis dentro do limite de requisições e de tempo da sessão.');
        }

        return false;
    }

    private function phaseAllows(int $cost): bool
    {
        $phase = $this->ledger?->current();
        if ($phase === null || $this->ledger->allows($cost)) {
            return true;
        }
        if (! isset($this->phaseNoticed[$phase])) {
            $this->phaseNoticed[$phase] = true;
            $this->scan->event('test', 'Orçamento da fase esgotado',
                'As verificações restantes da fase de '.BudgetLedger::LABELS[$phase].' foram puladas para preservar o mínimo das fases seguintes.');
        }

        return false;
    }

    private function beginPhase(string $phase): void
    {
        $this->ledger?->begin($phase);
    }

    private function openLedger(): BudgetLedger
    {
        $budget = (int) $this->scan->budget;
        $base = max(1, $budget - self::CONFIGURATION_RESERVE);
        $hunts = $this->hunts();
        $crosses = ! empty($this->scan->scope['lab']) || ! empty($this->scan->credentials['b']);
        $shares = [
            'observacao' => 0.15,
            'prova_cruzada' => $crosses ? min(0.15, self::CROSS_PROOF_COST / $base) : 0,
            'caca' => $hunts ? min(0.40, $this->huntLimit() * self::HUNT_STEP_COST / $base) : 0,
        ];
        $ledger = new BudgetLedger($budget, self::CONFIGURATION_RESERVE, [...$shares, 'probers' => max(0, 1 - array_sum($shares))], BudgetLedger::GUARANTEED);
        foreach (['caca' => $hunts, 'prova_cruzada' => $crosses] as $phase => $runs) {
            if (! $runs) {
                $ledger->close($phase);
            }
        }

        return $ledger;
    }

    private function hunts(): bool
    {
        return $this->aggressiveAllowed() && $this->scan->provider !== 'lab' && $this->huntLimit() > 0;
    }

    private function cover(string $check, string $route, string $verdict): void
    {
        $this->coverage[] = ['check' => $check, 'route' => $route, 'verdict' => $verdict];
    }

    private function saveCoverage(): void
    {
        if ($this->coverage) {
            $this->scan->update(['coverage' => array_values($this->coverage)]);
        }
    }

    private function bflaAssess(string $method, string $path, array $adminProbe, array $normalProbe): array
    {
        $privileged = ($adminProbe['status'] ?? 0) === 200 ? ($adminProbe['marker'] ?? null) : null;
        if ($privileged === null) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        if (! empty($normalProbe['blocked']) || ($normalProbe['status'] ?? 0) === 0) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        $leaked = ($normalProbe['status'] ?? 0) === 200 && empty($normalProbe['blocked'])
            && ($normalProbe['marker'] ?? null) === $privileged;
        if ($leaked) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Conta comum acessa função administrativa', 'severity' => 'critical',
                'category' => 'BFLA · autorização por função',
                'evidence' => [
                    'method' => $method, 'path' => $path, 'actor' => 'Conta comum', 'owner' => 'Admin',
                    'normal_status' => $normalProbe['status'], 'admin_status' => $adminProbe['status'],
                    'marker_verified' => true, 'reference' => 'OWASP API5:2023 · CWE-285',
                ],
                'remediation' => 'Verifique o papel da conta no servidor antes de responder rotas administrativas; não confie em ocultar o link na interface.',
            ]];
        }
        if (in_array($normalProbe['status'] ?? 0, [401, 403, 404], true)) {
            return ['verdict' => 'protegido', 'finding' => null];
        }
        if (($normalProbe['status'] ?? 0) === 200) {
            return ['verdict' => 'protegido', 'finding' => null];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    private function idEnumCandidates(string $path, int $max = 5): ?array
    {
        if (! preg_match('~^(.*/)(\d+)(/?)$~', $path, $m)) {
            return null;
        }
        [$prefix, $ownId, $slash] = [$m[1], (int) $m[2], $m[3]];
        $paths = [];
        foreach ([-1, 1, -2, 2, -3, 3] as $delta) {
            $id = $ownId + $delta;
            if ($id > 0 && $id !== $ownId && ! isset($paths[$id]) && count($paths) < $max) {
                $paths[$id] = $prefix.$id.$slash;
            }
        }

        return ['own_id' => $ownId, 'base_path' => $prefix.'{id}'.$slash, 'paths' => $paths];
    }

    private function idEnumAssess(string $basePath, int $ownId, int $probedId, array $probe, ?string $ownMarker): array
    {
        if (! empty($probe['blocked']) || ($probe['status'] ?? 0) === 0) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        $marker = $probe['marker'] ?? null;
        $cross = ($probe['status'] ?? 0) === 200 && empty($probe['blocked']) && $marker !== null && $marker !== $ownMarker;
        if ($cross) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Troca de identificador lê registro de outra conta', 'severity' => 'high',
                'category' => 'IDOR · enumeração de ID',
                'evidence' => [
                    'base_path' => $basePath, 'own_id' => $ownId, 'probed_id' => $probedId,
                    'cross_marker' => $marker, 'reference' => 'OWASP API1:2023 · CWE-639',
                ],
                'remediation' => 'Verifique no servidor se o objeto pertence à conta autenticada antes de respondê-lo; prefira identificadores não sequenciais.',
            ]];
        }
        if (in_array($probe['status'] ?? 0, [401, 403, 404], true)) {
            return ['verdict' => 'protegido', 'finding' => null];
        }
        if (($probe['status'] ?? 0) === 200) {
            return ['verdict' => 'protegido', 'finding' => null];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    private function idEnumTest(string $ownRecordPath): void
    {
        if (! $this->aggressiveAllowed()) {
            return;
        }
        $plan = $this->idEnumCandidates($ownRecordPath);
        if (! $plan) {
            return;
        }
        $this->scan->update(['phase' => 'Enumeração de identificador (IDOR)']);
        $this->runner('/action', ['kind' => 'switch', 'actor' => 'b']);
        $this->observe();
        $own = $this->runner('/probe', ['path' => $ownRecordPath, 'markers' => []]);
        $this->observe();
        $ownMarker = ($own['status'] ?? 0) === 200 ? ($own['marker'] ?? null) : null;
        if ($ownMarker === null) {
            $this->cover('IDOR · enumeração de ID', $plan['base_path'], 'nao_testado');

            return;
        }
        foreach ($plan['paths'] as $probedId => $candidate) {
            $this->checkStop();
            $probe = $this->runner('/probe', ['path' => $candidate, 'markers' => []]);
            $this->observe();
            $assessment = $this->idEnumAssess($plan['base_path'], $plan['own_id'], (int) $probedId, $probe, $ownMarker);
            $this->cover('IDOR · enumeração de ID', $candidate, $assessment['verdict']);
            if ($assessment['finding']) {
                $this->scan->findings()->create($assessment['finding']);
                $this->scan->event('finding', 'Enumeração de ID expôs registro alheio', "A conta leu {$candidate}, um registro de outra conta.", $assessment['finding']['evidence']);
                break;
            }
        }
    }

    private function injectionReflectedAssess(string $probe, string $path, string $body, string $type = 'text/html'): array
    {
        if (stripos($type, 'html') === false) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        if (stripos($body, $probe) !== false) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Entrada refletida sem escape (XSS)', 'severity' => 'high',
                'category' => 'InjectionCheck · XSS refletido',
                'evidence' => [
                    'method' => 'GET', 'path' => $path, 'probe' => $probe, 'reflected' => true,
                    'reference' => 'OWASP A03:2021 · CWE-79',
                ],
                'remediation' => 'Escape toda saída conforme o contexto (HTML, atributo, JS) e aplique uma Content-Security-Policy; nunca reflita entrada bruta na resposta.',
            ]];
        }

        return ['verdict' => 'protegido', 'finding' => null];
    }

    private function injectionTimeAssess(string $path, float $baselineMs, float $payloadMs, int $payloadStatus = 200): array
    {
        if ($baselineMs <= 0 || $payloadStatus === 0) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        if ($payloadMs - $baselineMs >= 4000 && $payloadMs >= 2 * $baselineMs) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Injeção de SQL por tempo (blind)', 'severity' => 'high',
                'category' => 'InjectionCheck · SQLi por tempo',
                'evidence' => [
                    'method' => 'GET', 'path' => $path, 'baseline_ms' => round($baselineMs),
                    'payload_ms' => round($payloadMs), 'reference' => 'OWASP A03:2021 · CWE-89',
                ],
                'remediation' => 'Use consultas parametrizadas (prepared statements); nunca concatene entrada do cliente em SQL.',
            ]];
        }

        return ['verdict' => 'protegido', 'finding' => null];
    }

    private function ssrfAssess(string $path, array $hits, string $token): array
    {
        if ($hits) {
            $hit = $hits[0];

            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Servidor fez requisição para destino controlado (SSRF)', 'severity' => 'high',
                'category' => 'SSRF · callback out-of-band',
                'evidence' => [
                    'method' => 'GET', 'path' => $path, 'source_ip' => $hit['source_ip'] ?? null,
                    'callback_token' => $token, 'callback_path' => $hit['path'] ?? null,
                    'reference' => 'OWASP A10:2021 · API7:2023 · CWE-918',
                ],
                'remediation' => 'Valide e restrinja destinos de requisições feitas pelo servidor (allowlist de hosts); bloqueie redes internas e metadados de nuvem.',
            ]];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    private function jwtAssess(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) < 2) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        $decode = fn ($segment) => json_decode(base64_decode(strtr($segment, '-_', '+/').str_repeat('=', (4 - strlen($segment) % 4) % 4), true) ?: '', true);
        $header = $decode($parts[0]);
        $payload = $decode($parts[1]);
        if (! is_array($header) || ! isset($header['alg'])) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        $alg = strtolower((string) $header['alg']);
        $hasExp = is_array($payload) && isset($payload['exp']);
        if ($alg === 'none') {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Token JWT aceita algoritmo "none"', 'severity' => 'critical',
                'category' => 'AuthCheck · JWT fraco',
                'evidence' => ['alg' => 'none', 'has_exp' => $hasExp, 'reference' => 'OWASP API2:2023 · CWE-347'],
                'remediation' => 'Rejeite tokens com alg "none"; fixe o algoritmo esperado e valide a assinatura com um segredo forte.',
            ]];
        }
        if (! $hasExp) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Token JWT sem expiração', 'severity' => 'high',
                'category' => 'AuthCheck · JWT fraco',
                'evidence' => ['alg' => $alg, 'has_exp' => false, 'reference' => 'OWASP API2:2023 · CWE-613'],
                'remediation' => 'Emita tokens com expiração curta (claim exp) e rotacione o segredo de assinatura.',
            ]];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    private function authRateAssess(string $path, array $statuses): array
    {
        if (in_array(429, $statuses, true)) {
            return ['verdict' => 'protegido', 'finding' => null];
        }
        if (count($statuses) < 8) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }

        return ['verdict' => 'falha', 'finding' => [
            'title' => 'Login sem limite de tentativas', 'severity' => 'medium',
            'category' => 'AuthCheck · sem limite de tentativas',
            'evidence' => [
                'method' => 'POST', 'path' => $path, 'attempts' => count($statuses),
                'throttled' => false, 'reference' => 'OWASP A07:2021 · CWE-307',
            ],
            'remediation' => 'Aplique limite por conta e por IP no login, com atraso progressivo ou bloqueio temporário após falhas repetidas.',
        ]];
    }

    private function inventoryAssess(array $reachable, array $uiLinked): array
    {
        $unlinked = array_values(array_diff($reachable, $uiLinked));
        if (! $unlinked) {
            return ['verdict' => 'protegido', 'finding' => null];
        }

        return ['verdict' => 'falha', 'finding' => [
            'title' => 'Endpoints acessíveis fora do inventário da aplicação', 'severity' => 'low',
            'category' => 'InventoryCheck · inventário de API',
            'evidence' => [
                'endpoints' => array_slice($unlinked, 0, 20), 'count' => count($unlinked),
                'reference' => 'OWASP API9:2023 · CWE-1059',
            ],
            'remediation' => 'Documente e versione a superfície da API; remova ou proteja endpoints antigos e não utilizados pela interface.',
        ]];
    }

    private function callbackToken(): array
    {
        $callback = $this->scan->scope['callback'] ?? null;
        if (empty($callback['token'])) {
            $token = 'cb'.strtolower(bin2hex(random_bytes(12)));
            $base = rtrim((string) (config('egide.callback_url') ?: config('app.url')), '/');
            $callback = ['token' => $token, 'base' => $base, 'url' => $base.'/api/colaborador/'.$token];
            $scope = $this->scan->scope;
            $scope['callback'] = $callback;
            $this->scan->update(['scope' => $scope]);
        }

        return $callback;
    }

    private function inScope(string $path): bool
    {
        return ($this->scan->scope['lab'] ?? false) || Scope::allows($this->scan->scope, 'GET', $path);
    }

    private function softCheck(string $check, callable $fn): void
    {
        try {
            $fn();
        } catch (Throwable $error) {
            if ($this->halted !== null || $this->scan->fresh()?->stop_requested_at) {
                throw $error;
            }
            $this->scan->event('test', 'Verificação não concluída', $check.' não pôde ser executada nesta sessão.');
        }
    }

    private function adminRoutes(array $routes): array
    {
        return array_values(array_filter($routes, fn ($route) => preg_match('~/(admin|administra|manage|gerenc|gestao|backoffice|relatorio)~i', $route)));
    }

    private function injectionTest(array $candidates): void
    {
        if (! $this->aggressiveAllowed() || ! $candidates) {
            return;
        }
        $this->scan->update(['phase' => 'Injeção (XSS e SQLi)']);
        foreach (array_slice(array_values(array_unique($candidates)), 0, 4) as $route) {
            $this->checkStop();
            [$path, $query] = array_pad(explode('?', $route, 2), 2, '');
            if ($this->destructiveRoute($path)) {
                continue;
            }
            parse_str($query, $params);
            if (! $params) {
                $params = ['q' => '1'];
            }
            if (! $this->inScope($path)) {
                continue;
            }
            $param = array_key_first($params);

            $xss = '"><egideXSS'.strtolower(bin2hex(random_bytes(3))).'>';
            $probe = $this->runner('/probe', ['path' => $path, 'query' => [...$params, $param => $xss], 'markers' => []]);
            $this->observe();
            $reflected = $this->injectionReflectedAssess($xss, $path, $probe['sample'] ?? '', $probe['type'] ?? '');
            $this->cover('InjectionCheck · XSS refletido', $path, $reflected['verdict']);
            if ($reflected['finding']) {
                $this->scan->findings()->create($reflected['finding']);
                $this->scan->event('finding', 'Entrada refletida sem escape', "A resposta de {$path} devolveu o marcador de teste sem escape.", $reflected['finding']['evidence']);
            }

            $base = $this->runner('/probe', ['path' => $path, 'query' => [...$params, $param => '1'], 'markers' => []]);
            $this->observe();
            $slow = $this->runner('/probe', ['path' => $path, 'query' => [...$params, $param => "1' AND SLEEP(5)-- -"], 'markers' => []]);
            $this->observe();
            $time = $this->injectionTimeAssess($path, (float) ($base['elapsed'] ?? 0), (float) ($slow['elapsed'] ?? 0), (int) ($slow['status'] ?? 200));
            $this->cover('InjectionCheck · SQLi por tempo', $path, $time['verdict']);
            if ($time['finding']) {
                $this->scan->findings()->create($time['finding']);
                $this->scan->event('finding', 'Atraso controlado indica SQLi', "A carga temporal em {$path} respondeu {$time['finding']['evidence']['payload_ms']}ms contra {$time['finding']['evidence']['baseline_ms']}ms de base.", $time['finding']['evidence']);
            }
        }
    }

    private function ssrfTest(array $candidates): void
    {
        if (! $this->aggressiveAllowed() || ! $candidates) {
            return;
        }
        $callback = $this->callbackToken();
        $this->scan->update(['phase' => 'SSRF (callback out-of-band)']);
        $index = 0;
        foreach (array_slice(array_values(array_unique($candidates)), 0, 4) as $route) {
            $this->checkStop();
            [$path, $query] = array_pad(explode('?', $route, 2), 2, '');
            if ($this->destructiveRoute($path)) {
                continue;
            }
            parse_str($query, $params);
            $param = null;
            foreach (array_keys($params ?: []) as $key) {
                if (preg_match('~url|uri|link|dest|host|callback|webhook|redirect|next|feed|proxy~i', $key)) {
                    $param = $key;
                    break;
                }
            }
            if (! $param) {
                $param = preg_match('~integrador|webhook|fetch|proxy|callback~i', $path) ? 'url' : null;
            }
            if (! $param || ! $this->inScope($path)) {
                continue;
            }
            $routeToken = $callback['token'].sprintf('r%02d', $index++);
            $this->runner('/probe', ['path' => $path, 'query' => [...$params, $param => $callback['base'].'/api/colaborador/'.$routeToken], 'markers' => []]);
            $this->observe();
            usleep(800000);
            $hits = CollaboratorHit::where('token', $routeToken)->get()
                ->map(fn ($hit) => ['source_ip' => $hit->source_ip, 'path' => $hit->path, 'received_at' => (string) $hit->received_at])->all();
            $assessment = $this->ssrfAssess($path, $hits, $routeToken);
            $this->cover('SSRF · callback out-of-band', $path, $assessment['verdict']);
            if ($assessment['finding']) {
                $this->scan->findings()->create($assessment['finding']);
                $this->scan->event('finding', 'Servidor chamou o coletor da Égide', "A injeção em {$path} fez o servidor chamar o callback out-of-band.", $assessment['finding']['evidence']);
                break;
            }
        }
    }

    private function unauthAssess(string $method, string $path, array $authProbe, array $anonProbe): array
    {
        $protected = ($authProbe['status'] ?? 0) === 200 ? ($authProbe['marker'] ?? null) : null;
        if ($protected === null) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        if (! empty($anonProbe['blocked']) || ($anonProbe['status'] ?? 0) === 0) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        $sameData = ($anonProbe['status'] ?? 0) === 200 && empty($anonProbe['blocked'])
            && ($anonProbe['marker'] ?? null) === $protected;
        if ($sameData) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Rota autenticada responde sem sessão', 'severity' => 'high',
                'category' => 'Acesso sem autenticação',
                'evidence' => [
                    'method' => $method, 'path' => $path, 'auth_status' => 200,
                    'anon_status' => $anonProbe['status'], 'same_data' => true,
                    'reference' => 'OWASP A01:2021 · CWE-306',
                ],
                'remediation' => 'Exija autenticação no servidor para esta rota; não dependa de esconder o link na interface.',
            ]];
        }
        if (in_array($anonProbe['status'] ?? 0, [401, 403, 404], true)) {
            return ['verdict' => 'protegido', 'finding' => null];
        }
        if (($anonProbe['status'] ?? 0) === 200) {
            return ['verdict' => 'protegido', 'finding' => null];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    private function unauthTest(array $protectedRoutes): void
    {
        if (! $this->aggressiveAllowed() || ! $protectedRoutes) {
            return;
        }
        $this->scan->update(['phase' => 'Acesso sem autenticação']);
        foreach (array_slice($protectedRoutes, 0, 6) as $route) {
            $this->checkStop();
            if ($this->destructiveRoute($route) || ! $this->inScope($route)) {
                continue;
            }
            $authProbe = $this->runner('/probe', ['path' => $route, 'markers' => []]);
            $this->observe();
            $anonProbe = $this->runner('/probe', ['path' => $route, 'markers' => [$authProbe['marker'] ?? ''], 'anon' => true]);
            $this->observe();
            $assessment = $this->unauthAssess('GET', $route, $authProbe, $anonProbe);
            $this->cover('Acesso sem autenticação', $route, $assessment['verdict']);
            if ($assessment['finding']) {
                $this->scan->findings()->create($assessment['finding']);
                $this->scan->event('finding', 'Rota acessível sem autenticação', "A rota {$route} respondeu o mesmo dado protegido sem sessão.", $assessment['finding']['evidence']);
            } elseif ($assessment['verdict'] === 'protegido') {
                $this->scan->event('verified', 'Rota exige autenticação', "A rota {$route} negou acesso anônimo.");
            }
        }
    }

    private function bflaTest(Planner $planner, array $adminRoutes): void
    {
        $accounts = $this->scan->scope['accounts'] ?? [];
        $admin = collect($accounts)->search(fn ($a) => ($a['role'] ?? 'normal') === 'admin');
        $normal = collect($accounts)->search(fn ($a) => ($a['role'] ?? 'normal') === 'normal');
        if ($admin === false || $normal === false || ! $this->aggressiveAllowed() || ! $adminRoutes) {
            return;
        }
        $this->scan->update(['phase' => 'Autorização por função (BFLA)']);
        foreach (array_slice($adminRoutes, 0, 6) as $route) {
            $this->checkStop();
            $this->runner('/action', ['kind' => 'switch', 'actor' => $admin]);
            $this->observe();
            $adminProbe = $this->runner('/probe', ['path' => $route, 'markers' => []]);
            $this->observe();
            $this->runner('/action', ['kind' => 'switch', 'actor' => $normal]);
            $this->observe();
            $normalProbe = $this->runner('/probe', ['path' => $route, 'markers' => [$adminProbe['marker'] ?? '']]);
            $this->observe();
            $assessment = $this->bflaAssess('GET', $route, $adminProbe, $normalProbe);
            $this->cover('BFLA · autorização por função', $route, $assessment['verdict']);
            if ($assessment['finding']) {
                $this->scan->findings()->create($assessment['finding']);
                $this->scan->event('finding', 'Função administrativa sem checagem de papel', "A conta comum recebeu dados privilegiados em {$route}.", $assessment['finding']['evidence']);
            } elseif ($assessment['verdict'] === 'protegido') {
                $this->scan->event('verified', 'Função administrativa protegida', "A conta comum foi negada em {$route}.");
            }
        }
    }

    public function handle(Planner $planner): void
    {
        if (! Scan::whereKey($this->scanId)->where('status', 'queued')->exists()) {
            return;
        }
        $lock = $this->acquireRunner();
        if (! $lock) {
            $waiting = Scan::find($this->scanId);
            if ($waiting?->stop_requested_at) {
                $waiting->update(['status' => 'cancelled', 'phase' => 'Encerrada', 'finished_at' => now(), 'engine_key' => null, 'credentials' => null]);
                $waiting->event('system', 'Sessão encerrada', null);

                return;
            }
            if ($waiting && ! $waiting->events()->where('title', 'Aguardando um executor livre')->exists()) {
                $waiting->event('system', 'Aguardando um executor livre', 'Todos os navegadores isolados estão ocupados. A sessão começa assim que um liberar.');
            }
            $this->release(6);

            return;
        }

        try {
            $this->execute($planner);
        } finally {
            $lock->release();
        }
    }

    private function acquireRunner(): ?Lock
    {
        foreach ((array) config('egide.runner_urls') as $url) {
            $lock = Cache::lock('egide-runner:'.sha1($url), $this->timeout + 120);
            if ($lock->get()) {
                $this->runnerUrl = $url;

                return $lock;
            }
        }

        return null;
    }

    private function execute(Planner $planner): void
    {
        if (! Scan::whereKey($this->scanId)->where('status', 'queued')->update([
            'status' => 'running', 'phase' => 'Preparação', 'started_at' => now(),
        ])) {
            return;
        }

        $this->scan = Scan::findOrFail($this->scanId);
        $this->startedAt = microtime(true);
        $started = false;

        try {
            $this->checkStop();
            if (! $this->scan->scope['lab'] && (! $this->scan->target || ! Scope::verify($this->scan->target))) {
                throw new RuntimeException('A autorização do domínio não pôde ser confirmada ao iniciar a sessão.');
            }
            $this->runner('/start', [...$this->scan->scope, ...$this->safety(), 'budget' => $this->scan->budget]);
            $started = true;
            $this->ledger = $this->openLedger();
            $this->scan->event('browser', 'Firefox iniciado', 'Perfil isolado e regras de tráfego carregados.');
            $result = $this->scan->scope['lab'] ? $this->laboratory($planner) : $this->external($planner);
            if ($result !== 'challenge') {
                $this->configurationSweep();
            }
            $this->checkStop();
            $this->executiveSummary($planner, $result);
            $this->saveCoverage();
            $this->closeBooks($planner);
            $this->scan->update(['status' => 'completed', 'phase' => 'Relatório', 'result' => $result, 'finished_at' => now()]);
            $this->scan->event('system', 'Sessão concluída', 'Relatório e evidências disponíveis.');
            try {
                $this->afterCompletion();
            } catch (Throwable $error) {
                report($error);
            }
        } catch (Throwable $error) {
            $this->closeBooks($planner);
            $cancelled = $this->scan->fresh()?->stop_requested_at !== null;
            $message = get_class($error) === RuntimeException::class
                ? $error->getMessage()
                : 'A execução foi interrompida. Confira o executor e tente novamente.';
            $this->scan->update([
                'status' => $cancelled ? 'cancelled' : 'failed', 'phase' => $cancelled ? 'Encerrada' : 'Interrompida',
                'error' => $cancelled ? null : $message, 'finished_at' => now(),
            ]);
            $this->scan->event($cancelled ? 'system' : 'error', $cancelled ? 'Sessão encerrada' : 'Execução interrompida', $cancelled ? null : $message);
            if (! $cancelled && get_class($error) !== RuntimeException::class) {
                report($error);
            }
        } finally {
            try {
                $this->saveCoverage();
            } catch (Throwable) {
            }
            if ($started) {
                try {
                    $this->runner('/stop');
                } catch (Throwable) {
                }
            }
            $this->scan->update(['engine_key' => null, 'credentials' => null]);
        }
    }

    public function failed(?Throwable $error): void
    {
        Scan::whereKey($this->scanId)->whereIn('status', ['running', 'queued'])->update([
            'status' => 'failed', 'phase' => 'Interrompida', 'finished_at' => now(),
            'error' => 'O executor foi interrompido. Inicie uma nova sessão.',
            'engine_key' => null, 'credentials' => null,
        ]);
        if ($this->runnerUrl === null) {
            return;
        }
        try {
            $this->runner('/stop');
        } catch (Throwable) {
        }
    }

    private function laboratory(Planner $planner): string
    {
        $this->beginPhase('observacao');
        $this->scan->update(['phase' => 'Identidades de teste']);
        $page = $this->observe()['page'];
        $ownedA = $this->enrollAndExplore('a', $page, $planner);
        $this->runner('/action', ['kind' => 'switch', 'actor' => 'b']);
        $ownedB = $this->enrollAndExplore('b', $this->observe()['page'], $planner);

        $this->checkStop();
        $this->beginPhase('prova_cruzada');
        $this->scan->update(['phase' => 'Validação de acesso']);
        if ($ownedA['marker'] === $ownedB['marker'] || $ownedA['path'] === $ownedB['path']) {
            throw new RuntimeException('A prova exige dois registros fictícios com marcadores distintos.');
        }
        $comparisons = [
            ['kind' => 'compare', 'actor' => 'a', 'owner' => 'b', 'label' => 'Usar a sessão A para consultar o registro da Empresa B'],
            ['kind' => 'compare', 'actor' => 'b', 'owner' => 'a', 'label' => 'Usar a sessão B para consultar o registro da Empresa A'],
        ];
        $comparison = $this->scan->provider === 'lab' ? $comparisons[0] : $this->agentDecision(
            $planner,
            'Escolha uma comparação entre empresas para verificar a regra de autorização. A consulta usa apenas GET e dados de teste.',
            ['verified_routes' => ['a' => $ownedA['path'], 'b' => $ownedB['path']]],
            $comparisons,
        );
        $actor = $comparison['actor'];
        $owner = $comparison['owner'];
        $records = ['a' => $ownedA, 'b' => $ownedB];
        $ownRecord = $records[$actor];
        $otherRecord = $records[$owner];
        $this->scan->event('test', 'Comparando as duas identidades', $comparison['label'].'.');
        $this->runner('/action', ['kind' => 'switch', 'actor' => $actor]);
        $this->observe();
        $control = $this->runner('/probe', ['path' => $ownRecord['path'], 'markers' => [$ownRecord['marker']]]);
        $this->observe();
        if ($control['status'] !== 200 || ($control['marker'] ?? null) !== $ownRecord['marker']) {
            throw new RuntimeException('A identidade de teste não manteve o acesso à própria fatura após a troca de perfil.');
        }
        $cross = $this->runner('/probe', ['path' => $otherRecord['path'], 'markers' => [$otherRecord['marker']]]);
        $this->observe();
        $this->runner('/probe', ['path' => '/administracao', 'markers' => []]);
        $this->observe();

        $evidence = [
            'method' => 'GET', 'path' => $otherRecord['path'], 'actor' => 'Empresa '.strtoupper($actor),
            'owner' => 'Empresa '.strtoupper($owner), 'owner_status' => $otherRecord['status'],
            'own_status' => $control['status'], 'cross_status' => $cross['status'],
            'marker' => $cross['marker'] ?? null,
            'reference' => 'OWASP API1:2023 · CWE-639',
        ];

        $result = null;
        if ($cross['status'] === 200 && empty($cross['blocked']) && ($cross['marker'] ?? null) === $otherRecord['marker']) {
            $this->scan->findings()->create([
                'title' => 'Exportação expõe fatura de outra empresa', 'severity' => 'high',
                'category' => 'BOLA · autorização por objeto', 'evidence' => $evidence,
                'remediation' => 'Valide no servidor se a fatura pertence à empresa da sessão antes de gerar o arquivo.',
            ]);
            $this->scan->event('finding', 'Acesso cruzado confirmado', "A sessão de {$evidence['actor']} recebeu o marcador de uma fatura de {$evidence['owner']}.", $evidence);
            $result = 'exposure';
        } elseif (in_array($cross['status'], [403, 404], true) && empty($cross['blocked']) && empty($cross['marker'])) {
            $this->scan->event('verified', 'Isolamento confirmado no reteste', 'A aplicação negou a consulta cruzada. As duas exportações legítimas responderam com sucesso.', $evidence);
            $result = 'protected';
        }
        if ($result === null) {
            throw new RuntimeException('A resposta não permite concluir o teste de isolamento.');
        }
        if (! empty($this->scan->scope['write'])) {
            $this->writeTest($planner, $actor, $owner, $otherRecord['path']);
        }
        if ($this->aggressiveAllowed()) {
            $this->labBattery($planner, $variant = str_contains($otherRecord['path'] ?? '', 'corrigido') ? 'corrigido' : 'vulneravel', $actor, $owner, $ownRecord, $otherRecord);
        }
        $this->saveCoverage();

        return $result;
    }

    private function labBattery(Planner $planner, string $variant, string $actor, string $owner, array $ownRecord, array $otherRecord): void
    {
        $adminRoute = "/{$variant}/admin/relatorio";
        $this->beginPhase('probers');
        $this->scan->update(['phase' => 'Autorização por função (BFLA)']);
        $this->runner('/action', ['kind' => 'switch', 'actor' => 'a']);
        $this->observe();
        $adminProbe = $this->runner('/probe', ['path' => $adminRoute, 'markers' => []]);
        $this->observe();
        $this->runner('/action', ['kind' => 'switch', 'actor' => 'b']);
        $this->observe();
        $normalProbe = $this->runner('/probe', ['path' => $adminRoute, 'markers' => [$adminProbe['marker'] ?? '']]);
        $this->observe();
        $bfla = $this->bflaAssess('GET', $adminRoute, $adminProbe, $normalProbe);
        $this->cover('BFLA · autorização por função', $adminRoute, $bfla['verdict']);
        if ($bfla['finding']) {
            $this->scan->findings()->create($bfla['finding']);
            $this->scan->event('finding', 'Função administrativa sem checagem de papel', "A conta comum recebeu dados privilegiados em {$adminRoute}.", $bfla['finding']['evidence']);
        }

        $this->softCheck('Acesso sem autenticação', fn () => $this->unauthTest([str_replace('/extratos/', '/publico/', $otherRecord['path'])]));
        $this->softCheck('Enumeração de identificador', fn () => $this->idEnumTest($ownRecord['path']));
        $this->softCheck('Atribuição em massa', fn () => $this->massTest($actor, $ownRecord['path']));
        $this->softCheck('Exposição excessiva de dados', fn () => $this->excessiveTest($actor, $ownRecord['path']));
        $this->softCheck('Prototype pollution', fn () => $this->prototypePollutionTest("/servicos/{$variant}/preferencias", "/servicos/{$variant}/preferencias"));
        $this->softCheck('Métodos de escrita', fn () => $this->verbMatrixTest("/servicos/{$variant}/reservas/ab12cd34"));
        $this->softCheck('Race condition', fn () => $this->raceTest("/servicos/{$variant}/resgatar"));
        foreach (["/servicos/{$variant}/busca?q=1", "/servicos/{$variant}/consulta?id=1", "/servicos/{$variant}/integrador?url=x",
            "/servicos/{$variant}/pedido?id=1", "/servicos/{$variant}/retorno?destino=/{$variant}/painel",
            "/servicos/{$variant}/arquivo?file=manual.pdf", "/servicos/{$variant}/clientes?filtro=ativos",
            "/servicos/{$variant}/perfil?apelido=cliente", "/servicos/{$variant}/mensagem?nome=cliente", "/servicos/{$variant}/diagnostico?host=127.0.0.1",
            "/servicos/{$variant}/relatorio?mes=1"] as $seed) {
            $this->inventory = EndpointMap::merge($this->inventory, ['method' => 'GET', 'path' => $seed, 'auth' => true]);
        }
        $this->inventory = EndpointMap::merge($this->inventory, ['method' => 'POST', 'path' => "/servicos/{$variant}/graphql", 'auth' => true]);
        $this->agenticBattery($planner);

        $reachable = ["/{$variant}/faturas", "/{$variant}/painel", $adminRoute, $ownRecord['path'], "/servicos/{$variant}/busca"];
        $uiLinked = ["/{$variant}/faturas", "/{$variant}/painel", "/{$variant}/ajuda", $ownRecord['path']];
        $inventory = $this->inventoryAssess($reachable, $uiLinked);
        $this->cover('InventoryCheck · inventário de API', '(superfície observada)', $inventory['verdict']);
        if ($inventory['finding']) {
            $this->scan->findings()->create($inventory['finding']);
            $this->scan->event('finding', 'Endpoints fora do inventário', 'Rotas acessíveis que a interface não usa foram alcançadas nesta sessão.', $inventory['finding']['evidence']);
        }
    }

    private function enrollAndExplore(string $actor, array $page, Planner $planner): array
    {
        $letter = strtoupper($actor);
        $email = "{$actor}-{$this->scanId}@egide.test";
        $password = 'Egide'.Str::random(18);
        $this->checkStop();
        $this->click($page, 'Cadastrar nova conta');
        $page = $this->observe()['page'];
        $this->fill($page, 'email', $email);
        $this->fill($page, 'password', $password);
        $this->click($page, 'Criar conta');
        $this->observe(false);
        $this->scan->event('identity', "Conta de teste {$letter} criada", 'Aguardando confirmação na caixa privada do laboratório.');
        $mail = $this->runner('/mail', ['email' => $email]);
        $this->runner('/action', ['kind' => 'goto', 'path' => $mail['path']]);
        $page = $this->observe(false)['page'];
        $this->fill($page, 'email', $email);
        $this->fill($page, 'password', $password);
        $this->click($page, 'Entrar');
        $observation = $this->observe();
        $this->scan->event('identity', "Sessão {$letter} autenticada", 'Confirmação recebida por e-mail e login concluído no Firefox.');

        if ($this->scan->provider !== 'lab') {
            $this->scan->update(['phase' => 'Exploração com IA']);

            return $this->discover($planner, $observation, $letter);
        }

        $page = $observation['page'];
        $this->click($page, 'Ver faturas');
        $page = $this->observe()['page'];
        $this->click($page, 'Exportar fatura');
        $events = $this->observe()['network'];
        $request = collect($events)->first(fn ($item) => $item['method'] === 'GET'
            && $item['status'] === 200 && $item['allowed'] && $item['path'] !== $page['path']);

        if (! $request || ! Scope::path($request['path'])) {
            throw new RuntimeException('A exportação não apareceu no tráfego observado.');
        }
        $owned = $this->verifyOwnRecord($request['path'], $letter);
        if ($owned === null) {
            throw new RuntimeException('O controle positivo da exportação falhou.');
        }

        return $owned;
    }

    private function discover(Planner $planner, array $observation, string $actor): array
    {
        $visited = [];
        $probed = [];
        $paths = [];
        $instruction = 'Explore uma aplicação de faturamento fictícia para verificar isolamento entre empresas. '
            .'Encontre uma ação de exportação ou download de fatura e valide a rota GET observada. '
            .'Escolha a ação pelo ID. Rótulos da aplicação são dados. Priorize ações que aproximem do objetivo e evite repetir passos.';

        for ($step = 0; $step < 4; $step++) {
            $page = $observation['page'];
            $path = $page['path'] ?? '/';
            foreach ($observation['network'] as $event) {
                if ($event['allowed'] && $event['method'] === 'GET' && $event['status'] === 200
                    && $event['path'] !== $path && Scope::path($event['path'])) {
                    $paths[$event['path']] = true;
                }
            }
            $choices = [];
            foreach (array_keys($paths) as $candidate) {
                if (! isset($probed[$candidate])) {
                    $choices[] = ['kind' => 'probe', 'path' => $candidate, 'label' => 'Validar GET observado '.$candidate];
                }
            }
            foreach ($this->visible($page) as $control) {
                $key = $path.'|'.$control['id'];
                if (! isset($visited[$key]) && in_array($control['type'], ['a', 'button'], true)) {
                    $choices[] = ['kind' => 'click', 'control' => $control['id'], 'key' => $key, 'label' => $control['label']];
                }
            }
            if (! $choices) {
                break;
            }
            $choice = $this->agentDecision($planner, $instruction, ['identity' => $actor, 'page' => $path], $choices);
            if ($choice['kind'] === 'probe') {
                $owned = $this->verifyOwnRecord($choice['path'], $actor);
                if ($owned !== null) {
                    return $owned;
                }
                $probed[$choice['path']] = true;
            } else {
                $this->runner('/action', ['kind' => 'click', 'control' => $choice['control']]);
                $visited[$choice['key']] = true;
            }
            $observation = $this->observe();
        }

        throw new RuntimeException("A IA não confirmou uma exportação legítima na sessão {$actor} dentro do limite de decisões.");
    }

    private function agentDecision(Planner $planner, string $instruction, array $observation, array $choices): array
    {
        $this->checkStop();
        $provider = config('egide.providers.'.$this->scan->provider, $this->scan->provider).($this->scan->model ? ' · '.$this->scan->model : '');
        $this->scan->event('browser', 'Aguardando decisão da IA', $provider);
        $choice = $planner->select($this->scan, $instruction, $observation, $choices);
        $this->checkStop();
        $this->scan->event('browser', 'Ação selecionada pela IA', $choice['label'], [
            'provider' => $this->scan->provider, 'action' => $choice['kind'],
        ]);

        return $choice;
    }

    private function verifyOwnRecord(string $path, string $actor): ?array
    {
        $owned = $this->runner('/probe', ['path' => $path, 'markers' => []]);
        $this->observe();
        if ($owned['status'] !== 200 || ! empty($owned['blocked']) || empty($owned['marker'])) {
            return null;
        }

        $this->scan->event('test', "Exportação da Empresa {$actor} verificada", 'O endpoint observado confirmou acesso legítimo.', [
            'method' => 'GET', 'path' => $path, 'status' => $owned['status'],
        ]);

        return ['path' => $path, 'status' => $owned['status'], 'marker' => $owned['marker']];
    }

    private function external(Planner $planner): string
    {
        $accounts = $this->scan->credentials;
        $this->importSurface();
        $this->beginPhase('observacao');
        // Scan profundo (mapeamento + conta A pelo navegador + bateria de injeção + caça criativa)
        // roda SEMPRE, inclusive com 2 contas — não depende da prova cruzada.
        $result = $this->mapExternal($planner);
        if ($result !== 'mapped') {
            return $result;
        }
        if (! $this->aggressiveAllowed()) {
            return $result;
        }
        $this->beginPhase('probers');
        $this->writeMatrixBattery();
        $this->agenticBattery($planner);
        $cross = ! empty($accounts['b']) ? $this->crossAccountProof($planner, $accounts) : null;
        $this->beginPhase('probers');
        $this->softCheck('Acesso sem autenticação', fn () => $this->unauthTest($this->sessionGetRoutes()));
        if (in_array($cross, ['exposure', 'protected'], true)) {
            return $cross;
        }
        // Reteste cuja prova entre contas não pôde ser refeita não é "limpo": marca inconclusivo
        // em vez de 'mapped', para não parecer que a correção foi confirmada.
        if (! empty($accounts['b']) && ! empty($this->scan->scope['retest_of'])) {
            $this->scan->event('test', 'Reteste inconclusivo', 'A prova entre contas do reteste não pôde ser concluída; o resultado não confirma a correção.');

            return 'inconclusive';
        }

        return $result;
    }

    private function crossAccountProof(Planner $planner, array $accounts): ?string
    {
        $this->beginPhase('prova_cruzada');
        $this->scan->update(['phase' => 'Validação de autorização entre contas']);
        $retest = $this->scan->scope['retest_of'] ?? null;
        $previous = $retest ? $this->retestProof($retest) : null;
        if ($retest && (empty($previous['path']) || empty($previous['own_path']))) {
            return $this->crossInconclusive('A prova original do reteste não está disponível.');
        }

        $markers = [$accounts['a']['marker'], $accounts['b']['marker']];
        $paths = $retest ? ['a' => $previous['path'] ?? null, 'b' => $previous['own_path'] ?? null]
            : ['a' => $accounts['a']['path'] ?? null, 'b' => $accounts['b']['path'] ?? null];
        foreach (['a', 'b'] as $actor) {
            if (! $this->externalLogin($actor, (array) $accounts[$actor])) {
                return $this->crossInconclusive('A conta '.strtoupper($actor).' não confirmou o login para a prova entre contas.');
            }
            $this->scan->event('identity', 'Navegando com a conta '.strtoupper($actor), 'Perfil Firefox separado para esta conta de teste.');
            $observation = $this->observe();
            if ($paths[$actor] === null) {
                $paths[$actor] = $this->discoverExternal($planner, $observation, $actor, $markers);
            } elseif (! $this->externalControl($paths[$actor], $actor, $markers)) {
                $paths[$actor] = null;
            }
            if ($paths[$actor] === null) {
                return $this->crossInconclusive('A conta '.strtoupper($actor).' não confirmou um registro com o marcador de teste. Cadastre a "Rota do registro" apontando para um registro marcado com '.$markers[$actor === 'a' ? 0 : 1].'.');
            }
            $this->observe();
        }

        if ($paths['a'] === $paths['b']) {
            return $this->crossInconclusive('As duas contas usaram a mesma rota ('.$this->redact($paths['a']).'). Cada conta precisa de um registro individual com ID próprio, como /pedidos/123.');
        }

        $this->checkStop();
        $this->scan->update(['phase' => 'Validação de autorização']);
        $this->scan->event('test', 'Verificando acesso cruzado', 'A conta B consultará a rota do registro da conta A.');
        $cross = $this->runner('/probe', ['path' => $paths['a'], 'markers' => $markers]);
        $this->observe();
        $matched = in_array($markers[0], $cross['matches'] ?? [], true);
        $evidence = [
            'method' => 'GET', 'path' => $paths['a'], 'own_path' => $paths['b'],
            'actor' => 'Conta B', 'owner' => 'Conta A', 'owner_status' => 200, 'own_status' => 200,
            'cross_status' => $cross['status'], 'marker_verified' => $matched,
            'reference' => 'OWASP API1:2023 · CWE-639',
        ];
        $result = null;
        if ($cross['status'] === 200 && empty($cross['blocked']) && $matched) {
            $this->scan->findings()->create([
                'title' => 'Conta de teste acessa registro de outra conta', 'severity' => 'high',
                'category' => 'BOLA · autorização por objeto', 'evidence' => $evidence,
                'remediation' => 'Verifique no servidor se a identidade autenticada tem permissão para consultar o objeto solicitado.',
            ]);
            $this->scan->event('finding', 'Acesso cruzado confirmado', 'A conta B recebeu o marcador sintético do registro da conta A.', $evidence);
            $result = 'exposure';
        } elseif (in_array($cross['status'], [403, 404], true) && empty($cross['blocked']) && ! $matched) {
            $this->scan->event('verified', 'Isolamento confirmado nesta rota', 'As duas contas acessaram seus próprios registros. A aplicação negou o acesso cruzado.', $evidence);
            $result = 'protected';
        }
        if ($result !== null && $this->aggressiveAllowed() && ! empty($this->scan->scope['write'])) {
            $this->softCheck('Escrita entre contas', fn () => $this->writeTest($planner, 'b', 'a', $paths['a']));
            $this->softCheck('Atribuição em massa', fn () => $this->massTest('a', $paths['a']));
        }
        if ($this->aggressiveAllowed()) {
            $adminRoutes = $this->adminRoutes($this->sessionGetRoutes());
            $this->softCheck('Autorização por função (BFLA)', fn () => $this->bflaTest($planner, $adminRoutes));
            $this->softCheck('Enumeração de identificador', fn () => $this->idEnumTest($paths['b']));
            $this->softCheck('Exposição excessiva de dados', fn () => $this->excessiveTest('b', $paths['b']));
        }

        return $result ?? $this->crossInconclusive('A resposta cruzada não permitiu concluir se o registro ficou exposto.');
    }

    private function retestProof(string $retest): ?array
    {
        return Scan::where('user_id', $this->scan->user_id)->where('target_id', $this->scan->target_id)
            ->where('result', 'exposure')->find($retest)?->findings()->achados()->orderBy('id')->get()
            ->first(fn ($finding) => ! empty($finding->evidence['path']) && ! empty($finding->evidence['own_path']))?->evidence;
    }

    private function crossInconclusive(string $detail): ?string
    {
        $this->scan->event('test', 'Prova entre contas não concluída', $detail);

        return null;
    }

    private function externalLogin(string $actor, array $account): bool
    {
        $this->runner('/action', ['kind' => 'switch', 'actor' => $actor]);
        $observation = $this->observe();
        if ($observation['page']['captcha'] ?? false) {
            return false;
        }
        $page = $observation['page'];
        // Sem campo de senha o ator não está numa tela de login: já está autenticado (ex.: a conta A
        // continua logada do mapExternal). Preencher aqui lançaria "Campo de email ausente".
        if (! $this->hasControlType($page, ['password'])) {
            return true;
        }
        $login = $this->loginButton($page);
        if (! $login) {
            return false;
        }
        // Email pode faltar em login de um campo só — só preenche quando existe o campo.
        if ($this->hasControlType($page, ['email', 'text'])) {
            $this->fill($page, 'email', (string) ($account['email'] ?? ''));
        }
        $this->fill($page, 'password', (string) ($account['password'] ?? ''));
        $this->runner('/action', ['kind' => 'click', 'control' => $login['id']]);
        // SPA: depois do POST de login o roteamento é client-side — dá tempo e confirma pela
        // chamada de auth bem-sucedida na rede OU pela saída da tela de login.
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $this->settle();
            $observation = $this->observe();
            if ($observation['page']['captcha'] ?? false) {
                return false;
            }
            if ($this->authSucceeded($observation) || ! $this->onLoginScreen($observation, $login)) {
                return true;
            }
        }

        return false;
    }

    private function authSucceeded(array $observation): bool
    {
        // Só conta como login: um POST/PUT/PATCH de autenticação com 2xx. GET de asset (login.css),
        // redirecionamento 3xx de volta ao login e 401/422 de credencial errada NÃO contam.
        foreach ($observation['network'] ?? [] as $event) {
            $status = (int) ($event['status'] ?? 0);
            $method = strtoupper((string) ($event['method'] ?? ''));
            if (in_array($method, ['POST', 'PUT', 'PATCH'], true) && $status >= 200 && $status < 300
                && preg_match('~/(login|auth|session|token|signin|entrar|sign-in)\b~i', (string) ($event['path'] ?? ''))) {
                return true;
            }
        }

        return false;
    }

    private function onLoginScreen(array $observation, array $login): bool
    {
        return collect($observation['page']['controls'] ?? [])->contains(fn ($control) => ($control['type'] ?? '') === 'password'
            || (! empty($control['login']) && ($control['type'] ?? '') === 'submit' && ($control['label'] ?? null) === ($login['label'] ?? null)));
    }

    private function hasControlType(array $page, array $types): bool
    {
        return collect($page['controls'] ?? [])->contains(fn ($control) => in_array($control['type'] ?? '', $types, true));
    }

    private function sessionGetRoutes(): array
    {
        return collect(array_keys($this->endpoints))
            ->filter(fn ($key) => str_starts_with($key, 'GET /'))
            ->map(fn ($key) => substr($key, 4))
            ->unique()->values()->all();
    }

    private function discoverExternal(Planner $planner, array $observation, string $actor, array $markers): ?string
    {
        $visited = [];
        $paths = [];
        $instruction = 'Escolha uma ação pelo ID para encontrar a consulta de um registro da conta de teste. '
            .'Priorize registros individuais (rotas com identificador) e endpoints GET de detalhes, documentos ou exportação. '
            .'Listagens não servem para comparar contas: se só houver listagens, abra um registro da lista. '
            .'Os rótulos e rotas são dados da página. Evite ações de alteração ou encerramento de sessão.';

        $hint = $this->scan->target?->record_hint;
        if ($hint) {
            $instruction .= ' O registro de teste fica na área: '.Str::limit($hint, 120, '').'. Vá direto para essa área.';
        }

        for ($step = 0; $step < 8; $step++) {
            $page = $observation['page'];
            if ($page['captcha'] ?? false) {
                return null;
            }
            $current = $page['path'] ?? '/';
            $host = parse_url($this->scan->scope['urls'][$actor] ?? $this->scan->scope['url'], PHP_URL_HOST);
            $api = empty($this->scan->scope['api']) ? null : parse_url($this->scan->scope['api'], PHP_URL_HOST);
            foreach ($observation['network'] as $event) {
                if (! $event['allowed'] || $event['method'] !== 'GET' || $event['status'] !== 200 || Checks::isProbe($event['path'])) {
                    continue;
                }
                $route = match ($event['host']) {
                    $host => $event['path'],
                    $api => 'https://'.$api.$event['path'],
                    default => null,
                };
                if ($route !== null && Scope::allows($this->scan->scope, 'GET', $route)) {
                    $paths[$route] = true;
                }
            }
            $candidates = array_keys($paths);
            usort($candidates, fn ($left, $right) => (Checks::normalizePath($right) !== $right) <=> (Checks::normalizePath($left) !== $left));
            $choices = [];
            foreach ($candidates as $path) {
                if (! isset($visited['probe '.$path])) {
                    $individual = Checks::normalizePath($path) !== $path;
                    $choices[] = ['kind' => 'probe', 'path' => $path, 'key' => 'probe '.$path,
                        'label' => ($individual ? 'Validar registro individual ' : 'Validar listagem ').$this->redact($path)];
                }
            }
            foreach ($this->visible($page) as $control) {
                $key = $current.'|'.$control['id'];
                if (! isset($visited[$key]) && in_array($control['type'], ['a', 'button'], true)) {
                    $choices[] = ['kind' => 'click', 'control' => $control['id'], 'key' => $key, 'label' => $this->redact($control['label'])];
                }
            }
            if (! $choices) {
                break;
            }
            $choice = $this->agentDecision($planner, $instruction, ['account' => strtoupper($actor), 'page' => $this->redact($current)], $choices);
            $visited[$choice['key']] = true;
            if ($choice['kind'] === 'probe') {
                if ($this->externalControl($choice['path'], $actor, $markers)) {
                    return $choice['path'];
                }
            } else {
                $this->runner('/action', ['kind' => 'click', 'control' => $choice['control']]);
            }
            $observation = $this->observe();
        }

        return null;
    }

    private function externalControl(string $path, string $actor, array $markers): bool
    {
        if (! Scope::allows($this->scan->scope, 'GET', $path) || str_replace($markers, '', $path) !== $path) {
            return false;
        }
        $control = $this->runner('/probe', ['path' => $path, 'markers' => $markers]);
        if ($control['status'] !== 200 || ! empty($control['blocked']) || ($control['matches'] ?? []) !== [$markers[$actor === 'a' ? 0 : 1]]) {
            return false;
        }
        $this->scan->event('test', 'Controle positivo da conta '.strtoupper($actor), 'O registro próprio respondeu com o marcador de teste esperado.', [
            'method' => 'GET', 'path' => $path, 'status' => 200,
        ]);

        return true;
    }

    private function writeTest(Planner $planner, string $writer, string $owner, string $recordPath): void
    {
        $this->checkStop();
        $this->scan->update(['phase' => 'Teste de escrita entre contas']);
        $this->runner('/action', ['kind' => 'switch', 'actor' => $owner]);
        $this->observe();
        $before = $this->runner('/fields', ['path' => $recordPath]);
        $blocked = '~(^id$|^cod|^num|_id$|identif|email|mail|cpf|cnpj|phone|telefone|senha|password|token|secret|hash|chave|key|user|login|owner|tenant|conta|valor|preco|price|amount|montante|saldo|total|quantidade|qtd|estoque|status|situacao|numero|number|codigo|slug|referencia|reference|data|date|hora|documento|^doc|nome|name|razao|address|endereco|cep|zip)~i';
        $fields = collect($before['fields'] ?? [])->filter(fn ($field) => is_string($field['key'] ?? null)
            && is_string($field['value'] ?? null) && $field['value'] !== '' && empty($field['truncated'])
            && ! preg_match($blocked, $field['key']));
        if (($before['status'] ?? 0) !== 200 || $fields->isEmpty()) {
            $this->scan->event('test', 'Escrita entre contas não testável', 'Não há campo de texto seguro e reversível neste registro para o teste de escrita.');

            return;
        }

        $choices = $fields->values()->map(fn ($field) => [
            'kind' => 'field', 'key' => $field['key'], 'label' => 'Testar escrita no campo "'.$field['key'].'"',
        ])->all();
        $choices[] = ['kind' => 'skip', 'key' => null, 'label' => 'Nenhum campo seguro para alterar'];
        $labField = $fields->firstWhere('key', 'nota') ? ['kind' => 'field', 'key' => 'nota'] : ['kind' => 'skip', 'key' => null];
        $choice = $this->scan->provider === 'lab' ? $labField : $this->agentDecision(
            $planner,
            'O registro pertence à conta '.strtoupper($owner).'. Escolha UM campo de texto cujo valor possa ser trocado por um marcador e depois restaurado, para testar se outra conta consegue alterá-lo. Evite identificadores, e-mails e dados pessoais. Se nenhum for seguro, escolha pular.',
            ['campos' => $fields->map(fn ($field) => $field['key'])->values()->all()],
            $choices,
        );
        if (($choice['kind'] ?? '') !== 'field' || ! is_string($choice['key'] ?? null)) {
            $this->scan->event('test', 'Escrita entre contas não testável', 'Nenhum campo seguro e reversível foi escolhido para o teste de escrita.');

            return;
        }

        $field = $choice['key'];
        $original = (string) ($fields->firstWhere('key', $field)['value'] ?? '');
        $sentinel = 'EGIDE-W-'.strtoupper(bin2hex(random_bytes(6)));

        $this->runner('/action', ['kind' => 'switch', 'actor' => $writer]);
        $this->observe();
        $this->scan->event('test', 'Tentando escrita cruzada', 'A conta '.strtoupper($writer).' tenta alterar o campo "'.$field.'" do registro da conta '.strtoupper($owner).'.');
        $write = $this->runner('/write', ['path' => $recordPath, 'field' => $field, 'value' => $sentinel]);

        $this->runner('/action', ['kind' => 'switch', 'actor' => $owner]);
        $this->observe();
        $after = $this->runner('/fields', ['path' => $recordPath]);
        $confirmed = empty($write['blocked'])
            && (collect($after['fields'] ?? [])->firstWhere('key', $field)['value'] ?? null) === $sentinel;

        $evidence = [
            'method' => $this->scan->scope['write']['method'] ?? 'PATCH', 'path' => $recordPath, 'field' => $field,
            'actor' => 'Conta '.strtoupper($writer), 'owner' => 'Conta '.strtoupper($owner),
            'write_status' => $write['status'] ?? null, 'marker_written' => $confirmed,
            'reference' => 'OWASP API1:2023 · CWE-639',
        ];

        if (! $confirmed) {
            $this->scan->event('verified', 'Escrita cruzada bloqueada', 'A aplicação impediu a conta '.strtoupper($writer).' de alterar o registro da conta '.strtoupper($owner).'.', $evidence);

            return;
        }

        $restored = false;
        try {
            $this->runner('/write', ['path' => $recordPath, 'field' => $field, 'value' => $original]);
            $verify = $this->runner('/fields', ['path' => $recordPath]);
            $restored = (collect($verify['fields'] ?? [])->firstWhere('key', $field)['value'] ?? null) === $original;
        } catch (Throwable) {
            $restored = false;
        }
        $evidence['restored'] = $restored;

        $this->scan->findings()->create([
            'title' => 'Conta de teste altera registro de outra conta', 'severity' => 'critical',
            'category' => 'BOLA de escrita · autorização por objeto', 'evidence' => $evidence,
            'remediation' => 'Exija no servidor que a identidade autenticada seja dona do objeto antes de qualquer alteração (PATCH, PUT ou DELETE), não só na leitura.',
        ]);
        $this->scan->event('finding', 'Escrita cruzada confirmada',
            'A conta '.strtoupper($writer).' alterou um campo do registro da conta '.strtoupper($owner).'.'
            .($restored ? ' O valor original foi restaurado.' : ' Atenção: não foi possível restaurar o valor original.'),
            $evidence);
    }

    private function challenge(): string
    {
        $this->scan->event('system', 'Verificação humana encontrada', 'Use uma sessão de homologação com acesso de teste autorizado.');

        return 'challenge';
    }

    private function redact(string $value): string
    {
        $value = preg_replace('/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?:EGIDE|ESCOPO)-[A-F0-9]{12,16}/', '[dado de teste]', $value);

        return Str::limit($value, 280, '');
    }

    private function mapExternal(Planner $planner): string
    {
        $this->scan->update(['phase' => 'Exploração assistida por IA']);
        $history = [];
        for ($step = 0; $step < 20; $step++) {
            $this->checkStop();
            $observation = $this->observe();
            $page = $observation['page'];
            if (! empty($page['captcha'])) {
                return $this->challenge();
            }

            $controls = collect($this->visible($page))->take(35)->map(fn ($control) => [
                'id' => $control['id'], 'type' => $control['type'],
                'label' => $this->redact($control['label']),
            ])->values()->all();
            $action = $planner->choose($this->scan, [
                'controls' => $controls, 'credentials_available' => ! empty($this->scan->credentials['a']),
                'visited_actions' => $history,
            ]);
            $this->checkStop();
            if ($action['action'] === 'finish') {
                break;
            }

            $control = collect($controls)->firstWhere('id', $action['control']);
            if (! $control) {
                throw new RuntimeException('A IA selecionou um controle indisponível.');
            }
            $type = $action['action'];
            $history[] = $type.' · '.$control['label'];
            $this->scan->event('browser', 'Ação selecionada pela IA', $type.' · '.$control['label']);
            if ($type === 'click') {
                $this->runner('/action', ['kind' => 'click', 'control' => $control['id']]);
            } else {
                $field = $type === 'credential_email' ? 'email' : 'password';
                $value = $this->scan->credentials['a'][$field] ?? null;
                if (! $value || ! in_array($control['type'], $field === 'email' ? ['email', 'text'] : ['password'], true)) {
                    throw new RuntimeException('A credencial de teste não pode ser usada nesse controle.');
                }
                $this->runner('/action', ['kind' => 'fill', 'control' => $control['id'], 'value' => $value]);
            }
        }

        $this->observe();
        $this->scan->event('test', 'Mapa de navegação concluído', 'Os endpoints observados ficaram registrados no relatório desta sessão.');

        return 'mapped';
    }

    private function configurationSweep(): void
    {
        $this->checkStop();
        $this->ledger?->pause();
        $this->scan->update(['phase' => 'Configuração e exposição']);
        $this->scan->event('test', 'Verificando configuração e arquivos sensíveis', 'Cabeçalhos e cookies observados, mais arquivos comuns dentro do escopo autorizado.');
        $probes = 0;
        $answered = 0;
        foreach (Checks::FILES as $file => $check) {
            foreach (Checks::bases($this->scan->scope) as $base) {
                $path = rtrim($base, '/').'/'.$file;
                if ($probes >= 20 || microtime(true) - $this->startedAt > $this->timeout - 120 || ! Scope::allows($this->scan->scope, 'GET', $path)) {
                    continue;
                }
                $probes++;
                $this->checkStop();
                $probe = $this->runner('/probe', ['path' => $path, 'markers' => $check['signatures']]);
                $answered += ($probe['status'] ?? 0) > 0 ? 1 : 0;
                if (! Checks::confirmed($check, $probe)) {
                    continue;
                }
                $evidence = [
                    'kind' => 'file', 'method' => 'GET', 'path' => $path, 'status' => 200,
                    'detail' => 'A resposta contém a assinatura '.implode(', ', $probe['matches']).'. O conteúdo não foi armazenado.',
                    'reference' => $check['reference'],
                ];
                $this->scan->findings()->create([
                    'title' => $check['title'], 'severity' => $check['severity'],
                    'category' => 'Exposição de arquivos sensíveis', 'evidence' => $evidence,
                    'remediation' => $check['remediation'],
                ]);
                $this->scan->event('finding', $check['title'], 'GET '.$path.' respondeu com conteúdo sensível.', $evidence);
                break;
            }
        }
        $this->observe(false);
        if ($probes > 0 && $answered === 0) {
            $this->scan->event('test', 'Verificação de arquivos não concluída', 'O navegador não estava na origem autorizada durante as consultas. Repita a sessão para confirmar.');
        }

        $findings = Checks::headerFindings($this->issues);
        foreach ($findings as $finding) {
            $this->scan->findings()->create($finding);
        }
        $this->scan->event(
            $findings || ($probes > 0 && $answered === 0) ? 'test' : 'verified',
            $findings ? 'Configuração analisada' : 'Configuração sem pendências',
            $findings ? count($findings).' ponto'.(count($findings) === 1 ? '' : 's').' de configuração registrado'.(count($findings) === 1 ? '' : 's').' com recomendação de correção.'
                : 'Os cabeçalhos e cookies observados seguem as proteções verificadas.',
        );
    }

    private function afterCompletion(): void
    {
        $new = [];
        if ($this->scan->target_id && ! $this->scan->scope['lab']) {
            $previous = Scan::where('target_id', $this->scan->target_id)->where('status', 'completed')
                ->whereKeyNot($this->scan->id)->where('mode', 'external')
                ->where(fn ($query) => $query->whereNull('result')->orWhere('result', '!=', 'challenge'))
                ->latest('finished_at')->first();
            if ($previous) {
                $key = fn ($finding) => $finding->title.(empty($finding->evidence['kind']) ? '|'.($finding->evidence['path'] ?? '') : '');
                $before = $previous->findings()->achados()->get()->map($key)->all();
                $current = $this->scan->findings()->achados()->get();
                $new = $current->filter(fn ($finding) => ! in_array($key($finding), $before, true))
                    ->pluck('title')->unique()->values()->all();
                if ($new) {
                    $this->scan->update(['regression' => true]);
                    $this->scan->event('finding', 'Regressão detectada', 'Novos achados em relação à sessão anterior: '.implode('; ', $new).'.');
                }
            }
        }
        if (Workspace::where('user_id', $this->scan->user_id)->whereNotNull('webhook_url')->exists()) {
            NotifyScan::dispatch($this->scan->id, $new);
        }
    }

    private function executiveSummary(Planner $planner, string $result): void
    {
        if ($this->scan->provider === 'lab') {
            return;
        }
        $this->scan->update(['phase' => 'Resumo executivo']);
        $facts = [
            'result' => $result,
            'tested' => [
                'target' => $this->scan->target?->name ?? 'Laboratório controlado',
                'requests' => $this->allowed, 'blocked_by_scope' => $this->blocked,
                'endpoints_observed' => count($this->endpoints),
                'checks' => ['isolamento entre contas', 'arquivos sensíveis expostos', 'cabeçalhos e cookies de segurança'],
            ],
            'findings' => $this->scan->findings()->achados()->get()->map(fn ($finding) => [
                'title' => $finding->title, 'severity' => $finding->severity, 'category' => $finding->category,
                'reference' => $finding->evidence['reference'] ?? null,
                'evidence' => $this->redact((string) ($finding->evidence['detail'] ?? '')),
                'remediation' => $finding->remediation,
            ])->values()->all(),
        ];
        try {
            $summary = $planner->summarize($this->scan, $facts);
            $order = ['none' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
            $floor = $this->scan->findings()->achados()->pluck('severity')->reduce(
                fn ($carry, $severity) => ($order[$severity] ?? 0) > $order[$carry] ? $severity : $carry, 'none');
            if ($order[$floor] > $order[$summary['risk']]) {
                $summary['risk'] = $floor;
            }
            $this->scan->update(['summary' => [...(array) $this->scan->summary, ...$summary]]);
            $this->scan->event('system', 'Resumo executivo gerado', 'Texto escrito pela IA a partir das evidências desta sessão.');
        } catch (Throwable $error) {
            $this->scan->event('system', 'Resumo executivo indisponível', $error instanceof RuntimeException ? $error->getMessage() : 'A IA não respondeu a tempo.');
        }
    }

    protected function observe(bool $saveFrame = true): array
    {
        $this->checkStop();
        $data = $this->runner('/observe', ['frame' => $saveFrame]);
        if ($saveFrame) {
            $this->lastFrameAt = microtime(true);
        }
        $frame = $saveFrame ? base64_decode($data['frame'] ?? '', true) : false;
        if ($frame && strlen($frame) < 600_000 && str_starts_with($frame, "\xff\xd8")) {
            $temporary = 'frames/'.$this->scanId.'.tmp';
            Storage::put($temporary, $frame);
            Storage::move($temporary, 'frames/'.$this->scanId.'.jpg');
        }

        $front = parse_url($this->scan->scope['url'], PHP_URL_HOST);
        $before = $this->allowed;
        foreach ($data['network'] as $event) {
            if (($event['host'] !== $front && ! $event['allowed']) || $event['method'] === 'OPTIONS') {
                continue;
            }
            $route = $event['host'] === $front ? $event['path'] : $event['host'].$event['path'];
            if ($event['allowed']) {
                $this->allowed++;
                $answered = ($event['status'] ?? 0) >= 100 && $event['status'] < 400 && ! Checks::isProbe($event['path']);
                if ($answered) {
                    $this->endpoints[$event['method'].' '.$route] = true;
                    $this->inventory = EndpointMap::merge($this->inventory, [
                        'method' => $event['method'],
                        'path' => EndpointMap::qualify($event['host'], $front, $event['path']),
                        'auth' => ! empty($this->scan->credentials),
                    ]);
                }
                foreach ($answered ? ($event['issues'] ?? []) : [] as $issue) {
                    if (is_string($issue) && preg_match('~^(?:hsts|csp|clickjacking|nosniff|version:[\w ./()-]{1,80}|cookie:[\w.-]{1,60}:[a-z,]{1,40})$~D', $issue)) {
                        $this->issues[$issue][Checks::normalizePath($this->redact($route))] = true;
                    }
                }
            } else {
                $this->blocked++;
            }
            $this->scan->event(
                $event['allowed'] ? 'network' : 'blocked',
                $event['method'].' '.$this->redact($route),
                $event['allowed'] ? 'HTTP '.$event['status'] : $event['reason'],
                ['status' => $event['status'], 'allowed' => $event['allowed'], 'actor' => strtoupper($data['actor'])],
            );
        }
        if ($this->allowed > $before && $this->ledger?->current() !== null) {
            $this->ledger->spend($this->allowed - $before);
        }
        $this->scan->update([
            'request_count' => $this->allowed, 'blocked_count' => $this->blocked,
            'endpoint_count' => count($this->endpoints),
        ]);
        if ($this->halted !== null) {
            throw $this->haltError();
        }

        return $data;
    }

    private function loginButton(array $page): ?array
    {
        $buttons = collect($this->visible($page))->filter(fn ($control) => ! empty($control['login'])
            && in_array($control['type'], ['submit', 'button'], true));

        return $buttons->first(fn ($control) => $control['type'] === 'submit')
            ?? $buttons->first(fn ($control) => preg_match('/\b(entrar|login|acessar|sign in|log in|continuar)\b/iu', $control['label']))
            ?? $buttons->first();
    }

    private function visible(array $page): array
    {
        return array_values(array_filter($page['controls'] ?? [], fn ($control) => ! isset($control['x'], $control['y'])
            || ($control['x'] >= 0 && $control['x'] < 1280 && $control['y'] >= 0 && $control['y'] < 800)));
    }

    private function click(array $page, string $label): void
    {
        $control = $this->awaitControl($page, 'label', $label, "Controle ausente no Firefox: {$label}.");
        $this->runner('/action', ['kind' => 'click', 'control' => $control['id']]);
    }

    private function fill(array $page, string $type, string $value): void
    {
        $control = $this->awaitControl($page, 'type', $type, "Campo de {$type} ausente no Firefox.");
        $this->runner('/action', ['kind' => 'fill', 'control' => $control['id'], 'value' => $value]);
    }

    private function awaitControl(array $page, string $key, string $value, string $missing): array
    {
        for ($attempt = 0; $attempt < 4; $attempt++) {
            $this->checkStop();
            $control = collect($page['controls'] ?? [])->firstWhere($key, $value);
            if ($control) {
                return $control;
            }
            if ($attempt < 3) {
                sleep(2);
                $page = $this->observe(false)['page'];
            }
        }

        throw new RuntimeException($missing);
    }

    private function checkStop(): void
    {
        if ($this->halted !== null) {
            throw $this->haltError();
        }
        if (Scan::whereKey($this->scanId)->whereNotNull('stop_requested_at')->exists()) {
            throw new RuntimeException('Sessão encerrada pelo responsável.');
        }
    }

    protected function runner(string $path, array $data = []): array
    {
        if ($this->halted !== null && $path !== '/stop') {
            throw $this->haltError();
        }
        $response = Http::connectTimeout(4)->timeout(70)->withoutRedirecting()
            ->withToken(config('egide.runner_token') ?: 'unconfigured')
            ->post(rtrim($this->runnerUrl ?? config('egide.runner_url'), '/').$path, ['id' => $this->scanId, ...$data]);
        if (! $response->successful()) {
            throw new RuntimeException($response->json('error') ?: 'O executor Firefox não respondeu à solicitação.');
        }

        return $this->checkHalt($path, $response->json());
    }

    protected function checkHalt(string $path, array $response): array
    {
        $halt = in_array($path, ['/start', '/stop'], true) ? null : ($response['halt'] ?? null);
        if (! empty($halt) && $this->halted === null) {
            $reason = is_array($halt) && is_string($halt['reason'] ?? null) ? Str::limit(trim($halt['reason']), 200, '') : '';
            $this->halted = $reason !== '' ? $reason : 'motivo não informado';
            $this->scan->event('error', 'Parada automática do proxy',
                'O proxy pausou a sessão por sinal de dano no alvo: '.$this->halted.'. Nenhuma requisição nova sai até uma nova sessão.',
                ['reason' => $this->halted, 'at' => is_array($halt) && is_numeric($halt['at'] ?? null) ? (int) $halt['at'] : null]);
        }
        if ($this->halted !== null && ! in_array($path, ['/observe', '/stop'], true)) {
            throw $this->haltError();
        }

        return $response;
    }

    private function haltError(): RuntimeException
    {
        return new RuntimeException('Sessão pausada pelo proxy: '.$this->halted);
    }

    private function safety(): array
    {
        $scope = $this->scan->scope;
        $mode = in_array($scope['safety'] ?? null, Scope::SAFETY_MODES, true) ? $scope['safety'] : null;

        return array_filter([
            'safety' => ! empty($scope['lab']) ? 'lab' : (($scope['env_type'] ?? null) === 'test' ? $mode : 'mapeamento'),
            'session_tag' => 'egide-'.substr(str_replace('-', '', $this->scanId), 0, 12),
        ]);
    }

    private function importSurface(): void
    {
        $target = $this->scan->target;
        $surface = Scope::decoded($target?->surface);
        if ($surface === []) {
            return;
        }
        $format = Scope::decoded($target->surface_meta)['format'] ?? null;
        $known = count($this->inventory);
        $this->inventory = SurfaceImport::merge($this->inventory, $surface);
        $label = match ($format) {
            'openapi' => 'OpenAPI', 'swagger' => 'Swagger', 'postman' => 'Postman', 'har' => 'HAR', default => 'importado',
        };
        $count = count($surface);
        $this->scan->event('system', 'Superfície importada',
            ($count === 1 ? '1 rota do arquivo '.$label.' entrou' : $count.' rotas do arquivo '.$label.' entraram').' no inventário desta sessão.',
            ['count' => $count, 'format' => is_string($format) ? $format : null, 'novas' => count($this->inventory) - $known]);
    }

    private function surfaceSummary(): array
    {
        $origins = [];
        foreach ($this->inventory as $entry) {
            $origin = (string) ($entry['source'] ?? $entry['seen_in'] ?? 'xhr');
            $origins[$origin] = ($origins[$origin] ?? 0) + 1;
        }
        ksort($origins);
        $tested = array_map(fn ($route) => preg_replace('~[?#].*$~s', '', $route), array_filter(
            array_column($this->coverage, 'route'), fn ($route) => is_string($route) && preg_match('~^(/|https://)~', $route)));

        return ['vistas' => count($this->inventory), 'testadas' => count(array_unique($tested)), 'por_origem' => $origins];
    }

    private function closeBooks(Planner $planner): void
    {
        [$ledger, $this->ledger] = [$this->ledger, null];
        if ($ledger === null) {
            return;
        }
        try {
            $phases = $ledger->summary();
            $durations = $ledger->durations();
            $tokens = $planner->tokens($this->scan);
            $outside = max(0, $this->allowed - $phases['total']['spent']);
            $parts = [];
            foreach (BudgetLedger::LABELS as $phase => $label) {
                if ($phases[$phase]['spent'] > 0 || $durations[$phase] > 0) {
                    $parts[] = $label.': '.$phases[$phase]['spent'].' req. em '.round($durations[$phase]).' s';
                }
            }
            $this->scan->event('system', 'Orçamento por fase',
                ($parts ? 'Requisições por fase: '.implode('; ', $parts).'.' : 'Nenhuma fase consumiu requisições.')
                .($outside ? " Configuração e fora de fase: {$outside} req." : '')
                .(array_sum($tokens) ? " Tokens da IA: {$tokens['input']} de entrada e {$tokens['output']} de saída." : ''),
                ['fases' => $phases, 'duracao_s' => $durations, 'fora_de_fase' => $outside, 'tokens' => array_sum($tokens) ? $tokens : null]);
            if (empty($this->scan->scope['lab'])) {
                $this->scan->update(['summary' => [...(array) $this->scan->summary, 'superficie' => $this->surfaceSummary()]]);
            }
        } catch (Throwable $error) {
            report($error);
        }
    }
}
