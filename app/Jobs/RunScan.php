<?php

namespace App\Jobs;

use App\Models\Scan;
use App\Models\Workspace;
use App\Security\Checks;
use App\Security\Planner;
use App\Security\Scope;
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
    use Queueable;

    public int $timeout = 600;

    public int $tries = 0;

    private ?string $runnerUrl = null;

    private Scan $scan;

    private array $endpoints = [];

    private int $allowed = 0;

    private int $blocked = 0;

    private array $issues = [];

    private float $startedAt = 0;

    public function __construct(public string $scanId) {}

    public function retryUntil(): \DateTimeInterface
    {
        return now()->addMinutes(45);
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
            $lock = Cache::lock('egide-runner:'.sha1($url), 900);
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
            $this->runner('/start', [...$this->scan->scope, 'budget' => $this->scan->budget]);
            $started = true;
            $this->scan->event('browser', 'Firefox iniciado', 'Perfil isolado e regras de tráfego carregados.');
            $result = $this->scan->scope['lab'] ? $this->laboratory($planner) : $this->external($planner);
            if ($result !== 'challenge') {
                $this->configurationSweep();
            }
            $this->checkStop();
            $this->executiveSummary($planner, $result);
            $this->scan->update(['status' => 'completed', 'phase' => 'Relatório', 'result' => $result, 'finished_at' => now()]);
            $this->scan->event('system', 'Sessão concluída', 'Relatório e evidências disponíveis.');
            try {
                $this->afterCompletion();
            } catch (Throwable $error) {
                report($error);
            }
        } catch (Throwable $error) {
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
        $this->scan->update(['phase' => 'Identidades de teste']);
        $page = $this->observe()['page'];
        $ownedA = $this->enrollAndExplore('a', $page, $planner);
        $this->runner('/action', ['kind' => 'switch', 'actor' => 'b']);
        $ownedB = $this->enrollAndExplore('b', $this->observe()['page'], $planner);

        $this->checkStop();
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

        return $result;
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
        if (empty($accounts['b'])) {
            return $this->mapExternal($planner);
        }

        $this->scan->update(['phase' => 'Exploração entre duas contas']);
        $retest = $this->scan->scope['retest_of'] ?? null;
        $previous = $retest ? Scan::where('user_id', $this->scan->user_id)->where('target_id', $this->scan->target_id)
            ->where('result', 'exposure')->find($retest)?->findings()->first()?->evidence : null;
        if ($retest && (empty($previous['path']) || empty($previous['own_path']))) {
            throw new RuntimeException('A prova original não está disponível para reteste.');
        }

        $markers = [$accounts['a']['marker'], $accounts['b']['marker']];
        $paths = $retest ? ['a' => $previous['path'] ?? null, 'b' => $previous['own_path'] ?? null]
            : ['a' => $accounts['a']['path'] ?? null, 'b' => $accounts['b']['path'] ?? null];
        foreach (['a', 'b'] as $actor) {
            $this->runner('/action', ['kind' => 'switch', 'actor' => $actor]);
            $observation = $this->observe();
            if ($observation['page']['captcha'] ?? false) {
                return $this->challenge();
            }
            $page = $observation['page'];
            $this->fill($page, 'email', $accounts[$actor]['email']);
            $this->fill($page, 'password', $accounts[$actor]['password']);
            $login = $this->loginButton($page);
            if (! $login) {
                return $this->inconclusive('O formulário de login não apresentou um botão de entrada reconhecível.');
            }
            $this->runner('/action', ['kind' => 'click', 'control' => $login['id']]);
            $observation = $this->observe();
            if ($observation['page']['captcha'] ?? false) {
                return $this->challenge();
            }
            $stillLogin = collect($observation['page']['controls'] ?? [])->contains(fn ($control) => $control['type'] === 'password'
                || (! empty($control['login']) && $control['type'] === 'submit' && $control['label'] === $login['label']));
            if ($stillLogin) {
                return $this->inconclusive('A conta '.strtoupper($actor).' não conseguiu sair da tela de login.');
            }
            $this->scan->event('identity', 'Navegando com a conta '.strtoupper($actor), 'Perfil Firefox separado para esta conta de teste.');

            if ($paths[$actor] === null) {
                $paths[$actor] = $this->discoverExternal($planner, $observation, $actor, $markers);
            } elseif (! $this->externalControl($paths[$actor], $actor, $markers)) {
                $paths[$actor] = null;
            }
            if ($paths[$actor] === null) {
                return $this->inconclusive('O GET autorizado da conta '.strtoupper($actor).' não confirmou exclusivamente o marcador de teste esperado.');
            }
            $this->observe();
        }

        if ($paths['a'] === $paths['b']) {
            return $this->inconclusive('As duas contas usaram a mesma rota ('.$this->redact($paths['a']).'). Para comparar, cada conta precisa de um registro individual com identificador próprio, como /pedidos/123.');
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
        if ($result !== null && ! empty($this->scan->scope['write'])) {
            $this->writeTest($planner, 'b', 'a', $paths['a']);
        }

        return $result ?? $this->inconclusive('A resposta cruzada não permitiu concluir se o registro ficou exposto.', $evidence);
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

    private function inconclusive(string $detail, ?array $evidence = null): string
    {
        $this->scan->event('test', 'Prova inconclusiva', $detail, $evidence);

        return 'inconclusive';
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
        for ($step = 0; $step < 8; $step++) {
            $this->checkStop();
            $observation = $this->observe(empty($this->scan->credentials['a']));
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

        $this->observe(empty($this->scan->credentials['a']));
        $this->scan->event('test', 'Mapa de navegação concluído', 'Os endpoints observados ficaram registrados no relatório desta sessão.');

        return 'mapped';
    }

    private function configurationSweep(): void
    {
        $this->checkStop();
        $this->scan->update(['phase' => 'Configuração e exposição']);
        $this->scan->event('test', 'Verificando configuração e arquivos sensíveis', 'Cabeçalhos e cookies observados, mais arquivos comuns dentro do escopo autorizado.');
        $probes = 0;
        $answered = 0;
        foreach (Checks::FILES as $file => $check) {
            foreach (Checks::bases($this->scan->scope) as $base) {
                $path = rtrim($base, '/').'/'.$file;
                if ($probes >= 14 || microtime(true) - $this->startedAt > 480 || ! Scope::allows($this->scan->scope, 'GET', $path)) {
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
                $before = $previous->findings()->get()->map($key)->all();
                $current = $this->scan->findings()->get();
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
            'findings' => $this->scan->findings()->get()->map(fn ($finding) => [
                'title' => $finding->title, 'severity' => $finding->severity, 'category' => $finding->category,
                'reference' => $finding->evidence['reference'] ?? null,
                'evidence' => $this->redact((string) ($finding->evidence['detail'] ?? '')),
                'remediation' => $finding->remediation,
            ])->values()->all(),
        ];
        try {
            $summary = $planner->summarize($this->scan, $facts);
            $order = ['none' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
            $floor = $this->scan->findings()->pluck('severity')->reduce(
                fn ($carry, $severity) => ($order[$severity] ?? 0) > $order[$carry] ? $severity : $carry, 'none');
            if ($order[$floor] > $order[$summary['risk']]) {
                $summary['risk'] = $floor;
            }
            $this->scan->update(['summary' => $summary]);
            $this->scan->event('system', 'Resumo executivo gerado', 'Texto escrito pela IA a partir das evidências desta sessão.');
        } catch (Throwable $error) {
            $this->scan->event('system', 'Resumo executivo indisponível', $error instanceof RuntimeException ? $error->getMessage() : 'A IA não respondeu a tempo.');
        }
    }

    private function observe(bool $saveFrame = true): array
    {
        $this->checkStop();
        $data = $this->runner('/observe', ['frame' => $saveFrame]);
        $frame = $saveFrame ? base64_decode($data['frame'] ?? '', true) : false;
        if ($frame && strlen($frame) < 600_000 && str_starts_with($frame, "\xff\xd8")) {
            $temporary = 'frames/'.$this->scanId.'.tmp';
            Storage::put($temporary, $frame);
            Storage::move($temporary, 'frames/'.$this->scanId.'.jpg');
        }

        $front = parse_url($this->scan->scope['url'], PHP_URL_HOST);
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
        $this->scan->update([
            'request_count' => $this->allowed, 'blocked_count' => $this->blocked,
            'endpoint_count' => count($this->endpoints),
        ]);

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
        if (Scan::whereKey($this->scanId)->whereNotNull('stop_requested_at')->exists()) {
            throw new RuntimeException('Sessão encerrada pelo responsável.');
        }
    }

    private function runner(string $path, array $data = []): array
    {
        $response = Http::connectTimeout(4)->timeout(70)->withoutRedirecting()
            ->withToken(config('egide.runner_token') ?: 'unconfigured')
            ->post(rtrim($this->runnerUrl ?? config('egide.runner_url'), '/').$path, ['id' => $this->scanId, ...$data]);
        if (! $response->successful()) {
            throw new RuntimeException($response->json('error') ?: 'O executor Firefox não respondeu à solicitação.');
        }

        return $response->json();
    }
}
