<?php

namespace App\Http\Controllers;

use App\Jobs\RunScan;
use App\Models\ApiToken;
use App\Models\Finding;
use App\Models\Platform;
use App\Models\Scan;
use App\Models\Target;
use App\Models\Workspace;
use App\Security\Demo;
use App\Security\Engine;
use App\Security\Scope;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;

class ConsoleController extends Controller
{
    public function index(Request $request)
    {
        $owner = $request->user()->id;
        $scans = Scan::where('user_id', $owner);
        $findings = Finding::whereIn('scan_id', (clone $scans)->select('id'));

        $spotlight = (clone $scans)->whereIn('status', ['queued', 'running'])->latest()->first()
            ?? (clone $scans)->where('status', 'completed')->latest('finished_at')->first();

        return Inertia::render('Overview', [
            'agentAvailable' => $this->engine($this->workspace($request)) !== null,
            'scans' => (clone $scans)->latest()->limit(6)->get(),
            'spotlight' => $spotlight ? [
                ...$spotlight->only(['id', 'name', 'status', 'phase', 'result', 'model', 'request_count', 'budget', 'blocked_count', 'started_at', 'finished_at', 'updated_at']),
                'engine' => config('egide.providers.'.$spotlight->provider, $spotlight->provider),
                'risk' => $spotlight->summary['risk'] ?? null,
                'frame' => Storage::exists('frames/'.$spotlight->id.'.jpg'),
                'frame_at' => $this->frameAt($spotlight->id),
                'events' => $spotlight->events()->whereIn('type', ['browser', 'test', 'finding', 'verified', 'identity'])
                    ->where('title', '!=', 'Aguardando decisão da IA')->latest('id')->limit(5)->get(['id', 'type', 'title', 'detail', 'created_at']),
                'severity' => $spotlight->findings()->get()->countBy('severity'),
            ] : null,
            'stats' => [
                'assets' => Target::where('user_id', $owner)->whereNotNull('verified_at')->count(),
                'sessions' => (clone $scans)->where('status', 'completed')->count(),
                'findings' => $findings->count(),
                'active' => (clone $scans)->whereIn('status', ['queued', 'running'])->count(),
            ],
        ]);
    }

    public function assets(Request $request)
    {
        return Inertia::render('Assets', [
            'targets' => Target::where('user_id', $request->user()->id)->latest()->get()->map(fn (Target $target) => [
                ...$target->toArray(),
                'verify_urls' => array_map(fn ($origin) => $origin.'/.well-known/egide-verification.txt', Scope::origins($target)),
                'verify_dns' => array_map(fn ($domain) => [
                    'domain' => $domain, 'host' => '_egide-verification', 'name' => '_egide-verification.'.$domain,
                    'value' => $target->verification_token,
                ], Scope::dnsDomains($target)),
                'edit' => $this->editData($target),
            ]),
            'localTargets' => Scope::localEnabled(),
        ]);
    }

    public function createTarget(Request $request)
    {
        $attrs = $this->buildTarget($request, null);
        Target::create([
            'user_id' => $request->user()->id, 'verification_token' => Str::random(48),
            'verified_at' => $attrs['local_port'] !== null ? now() : null, ...$attrs,
        ]);

        return back()->with('notice', $attrs['local_port'] !== null
            ? 'Ambiente local cadastrado. O executor acessa a porta '.$attrs['local_port'].' da sua máquina, sem passar pela internet.'
            : 'Ambiente cadastrado. Publique o código para verificar o domínio.');
    }

    public function updateTarget(Request $request, Target $target)
    {
        $this->owns($request, $target->user_id);
        $before = Scope::origins($target);
        $attrs = $this->buildTarget($request, $target);
        $after = array_values(array_filter([$attrs['origin'], $attrs['api_origin'],
            ...array_map(fn ($account) => $account['origin'] ?? null, (array) $attrs['credentials'])]));
        $reverify = $attrs['local_port'] === null && array_values(array_unique($after)) !== $before;
        $target->update([
            ...$attrs,
            'verified_at' => $attrs['local_port'] !== null ? now() : ($reverify ? null : $target->verified_at),
        ]);

        return back()->with('notice', $reverify
            ? 'Ambiente atualizado. O domínio mudou, verifique novamente.'
            : 'Ambiente atualizado.');
    }

    private function buildTarget(Request $request, ?Target $existing): array
    {
        $data = $request->validate([
            'name' => 'required|string|max:100', 'origin' => 'required|string|max:220', 'api_origin' => 'nullable|string|max:220',
            'entry_path' => 'required|string|max:180', 'rules' => 'required|string|max:1600',
            'denied' => 'nullable|string|max:800',
            'email_a' => 'nullable|string|max:180',
            'password_a' => 'nullable|string|max:200',
            'email_b' => 'nullable|string|max:180|required_with:marker_a,marker_b',
            'password_b' => 'nullable|string|max:200',
            'marker_a' => ['nullable', 'required_with:email_b', 'regex:/^(?:EGIDE|ESCOPO)-[A-F0-9]{16}$/D'],
            'marker_b' => ['nullable', 'required_with:email_b', 'different:marker_a', 'regex:/^(?:EGIDE|ESCOPO)-[A-F0-9]{16}$/D'],
            'origin_a' => 'nullable|string|max:220', 'origin_b' => 'nullable|string|max:220',
            'local_port' => 'nullable|integer|min:1|max:65535',
            'record_hint' => 'nullable|string|max:120',
            'path_a' => 'nullable|string|max:250', 'path_b' => 'nullable|string|max:250',
            'role_a' => 'nullable|in:admin,normal', 'role_b' => 'nullable|in:admin,normal',
            'environment_type' => 'nullable|in:test,production',
            'write_test' => 'sometimes|boolean',
        ]);
        $existingCredentials = (array) ($existing?->credentials ?? []);
        $origin = Scope::origin($data['origin']);
        $localPort = $data['local_port'] ?? null;
        if ($localPort !== null && in_array((int) $localPort, Scope::RESERVED_PORTS, true)) {
            throw ValidationException::withMessages(['local_port' => 'Essa porta é de um serviço de infraestrutura. Informe a porta do app web.']);
        }
        if ($localPort !== null && (! Scope::localEnabled() || ! Scope::isLocalOrigin($origin))) {
            throw ValidationException::withMessages(['local_port' => 'O modo local exige a Égide AI em ambiente local e uma origem terminada em '.Scope::LOCAL_SUFFIX.'.']);
        }
        if ($localPort === null && Scope::isLocalOrigin($origin)) {
            throw ValidationException::withMessages(['origin' => 'Origens '.Scope::LOCAL_SUFFIX.' só funcionam no modo local, com a porta informada.']);
        }
        $apiOrigin = empty($data['api_origin']) ? null : Scope::origin($data['api_origin'], 'api_origin');
        if ($apiOrigin !== null && $localPort !== null) {
            throw ValidationException::withMessages(['api_origin' => 'No modo local, a API entra pelo mesmo endereço com --rota no egide-local.']);
        }
        if ($apiOrigin !== null && Scope::isLocalOrigin($apiOrigin)) {
            throw ValidationException::withMessages(['api_origin' => 'Origens '.Scope::LOCAL_SUFFIX.' só funcionam no modo local, com a porta informada.']);
        }
        if ($apiOrigin === $origin) {
            throw ValidationException::withMessages(['api_origin' => 'A API já está no mesmo domínio. Escolha "No mesmo domínio".']);
        }
        $entryPath = $data['entry_path'];
        $rules = Scope::rules($data['rules']);
        $denied = array_values(array_filter(array_map('trim', preg_split('/\R/', $data['denied'] ?? ''))));

        if (! Scope::path($entryPath) || array_filter($denied, fn ($path) => ! Scope::path($path) || $path === '/')) {
            throw ValidationException::withMessages(['entry_path' => 'Use caminhos como /login ou /administracao.']);
        }
        if (! Scope::allows(compact('rules', 'denied'), 'GET', $entryPath)) {
            throw ValidationException::withMessages(['rules' => 'Permita GET no caminho de entrada e retire-o dos bloqueios.']);
        }
        $duplicate = Target::where('user_id', $request->user()->id)->where('origin', $origin);
        if ($existing) {
            $duplicate->whereKeyNot($existing->id);
        }
        if ($duplicate->exists()) {
            throw ValidationException::withMessages(['origin' => 'Este domínio já está cadastrado no workspace.']);
        }
        $credentials = [];
        if (! empty($data['email_b']) && (empty($data['email_a']) || strcasecmp($data['email_a'], $data['email_b']) === 0)) {
            throw ValidationException::withMessages(['email_b' => 'Informe duas contas de teste distintas.']);
        }
        foreach (['a', 'b'] as $actor) {
            if (! empty($data['email_'.$actor])) {
                $accountOrigin = empty($data['origin_'.$actor]) ? null : Scope::origin($data['origin_'.$actor], 'origin_'.$actor);
                if ($accountOrigin && $localPort === null && Scope::isLocalOrigin($accountOrigin)) {
                    throw ValidationException::withMessages(['origin_'.$actor => 'Subdomínios '.Scope::LOCAL_SUFFIX.' só funcionam no modo local, com a porta informada.']);
                }
                if ($accountOrigin && $localPort !== null && ! Scope::isLocalOrigin($accountOrigin)) {
                    throw ValidationException::withMessages(['origin_'.$actor => 'No modo local, use um subdomínio terminado em '.Scope::LOCAL_SUFFIX.'.']);
                }
                if ($accountOrigin && ! Scope::sibling($origin, $accountOrigin)) {
                    throw ValidationException::withMessages(['origin_'.$actor => 'Use um subdomínio do mesmo domínio do ambiente, como https://empresa-a.seuapp.com.br.']);
                }
                $recordPath = $data['path_'.$actor] ?? null;
                if ($recordPath !== null && $apiOrigin !== null && str_starts_with($recordPath, '/')) {
                    $recordPath = $apiOrigin.$recordPath;
                }
                if ($recordPath !== null && ! Scope::allows(['rules' => $rules, 'denied' => $denied, 'api' => $apiOrigin], 'GET', $recordPath)) {
                    throw ValidationException::withMessages(['path_'.$actor => $apiOrigin
                        ? 'Use uma rota GET permitida da API, como /pedidos/123.'
                        : 'Use uma rota GET permitida pelas regras, sem parâmetros, como /api/pedidos/123.']);
                }
                $stored = $existingCredentials[$actor] ?? null;
                $password = $data['password_'.$actor] ?? null;
                if (($password === null || $password === '') && $stored && strcasecmp($stored['email'] ?? '', $data['email_'.$actor]) === 0) {
                    $password = $stored['password'] ?? null;
                }
                if ($password === null || $password === '') {
                    throw ValidationException::withMessages(['password_'.$actor => 'Informe a senha da conta de teste '.strtoupper($actor).'.']);
                }
                $credentials[$actor] = [
                    'email' => $data['email_'.$actor], 'password' => $password,
                    'marker' => $data['marker_'.$actor] ?? null, 'origin' => $accountOrigin, 'path' => $recordPath,
                    'role' => $data['role_'.$actor] ?? 'normal',
                ];
            }
        }

        if (isset($credentials['a']['path'], $credentials['b']['path']) && $credentials['a']['path'] === $credentials['b']['path']
            && ($credentials['a']['origin'] ?? $origin) === ($credentials['b']['origin'] ?? $origin)) {
            throw ValidationException::withMessages(['path_b' => 'Cada conta precisa de um registro com rota própria.']);
        }

        $writeTest = ! empty($data['write_test']);
        if ($writeTest && (empty($credentials['b']) || empty($credentials['a']['path']))) {
            throw ValidationException::withMessages(['path_a' => 'Para testar escrita, informe duas contas e a rota do registro da conta A.']);
        }

        return [
            'name' => $data['name'], 'origin' => $origin, 'api_origin' => $apiOrigin, 'entry_path' => $entryPath,
            'rules' => $rules, 'denied' => $denied, 'credentials' => $credentials ?: null,
            'local_port' => $localPort, 'write_test' => $writeTest,
            'environment_type' => $data['environment_type'] ?? 'production',
            'record_hint' => isset($data['record_hint']) ? trim($data['record_hint']) : null,
        ];
    }

    public function deleteTarget(Request $request, Target $target)
    {
        $this->owns($request, $target->user_id);
        Scan::where('target_id', $target->id)->update(['target_id' => null]);
        $target->delete();

        return back()->with('notice', 'Ambiente removido.');
    }

    private function editData(Target $target): array
    {
        $api = $target->api_origin;
        $rules = collect($target->rules)->map(fn ($rule) => $rule['method'].' '
            .($rule['prefix'] ? ($rule['path'] === '/' ? '/*' : $rule['path'].'/*') : $rule['path']))->implode("\n");
        $accounts = collect(['a', 'b'])->mapWithKeys(function ($actor) use ($target, $api) {
            $account = $target->credentials[$actor] ?? null;
            $path = $account['path'] ?? '';
            if ($api && is_string($path) && str_starts_with($path, $api)) {
                $path = substr($path, strlen($api));
            }

            return [$actor => [
                'email' => $account['email'] ?? '', 'marker' => $account['marker'] ?? '',
                'origin' => $account['origin'] ?? '', 'path' => $path,
                'role' => $account['role'] ?? 'normal',
            ]];
        })->all();

        return [
            'name' => $target->name, 'origin' => $target->origin, 'api_origin' => $api ?? '',
            'entry_path' => $target->entry_path, 'record_hint' => $target->record_hint ?? '',
            'write_test' => (bool) $target->write_test, 'rules' => $rules,
            'environment_type' => $target->environment_type ?? 'production',
            'denied' => implode("\n", (array) $target->denied), 'accounts' => $accounts,
        ];
    }

    public function verifyTarget(Request $request, Target $target)
    {
        $this->owns($request, $target->user_id);
        if (! Scope::verify($target)) {
            $target->update(['verified_at' => null]);

            return back()->withErrors(['verification' => 'O arquivo HTTPS precisa responder com o código exibido, sem redirecionamento.']);
        }

        $target->update(['verified_at' => now()]);

        return back()->with('notice', 'Domínio verificado.');
    }

    public function sessions(Request $request)
    {
        $filter = in_array($request->query('filtro'), ['ativas', 'achados'], true) ? $request->query('filtro') : 'todas';
        $base = fn () => Scan::where('user_id', $request->user()->id);
        $query = $base()->withCount('findings')->latest();
        if ($filter === 'ativas') {
            $query->whereIn('status', ['queued', 'running']);
        } elseif ($filter === 'achados') {
            $query->has('findings');
        }

        return Inertia::render('Sessions', [
            'scans' => $query->paginate(20)->withQueryString(),
            'filter' => $filter,
            'counts' => [
                'todas' => $base()->count(),
                'ativas' => $base()->whereIn('status', ['queued', 'running'])->count(),
                'achados' => $base()->has('findings')->count(),
            ],
        ]);
    }

    public function sessionForm(Request $request)
    {
        $workspace = $this->workspace($request);
        $engine = $this->engine($workspace);
        $externalEngine = $this->engine($workspace, true);
        $retest = $request->query('retest');
        $previous = is_string($retest) && Str::isUuid($retest) ? Scan::where('user_id', $request->user()->id)
            ->where('mode', 'external')->where('result', 'exposure')->find($retest) : null;
        $targets = Target::where('user_id', $request->user()->id)->whereNotNull('verified_at')->get();

        return Inertia::render('NewSession', [
            'targets' => $targets->map(fn (Target $target) => [
                ...$target->only(['id', 'name', 'origin']), 'comparison' => isset($target->credentials['b']),
            ]),
            'externalEngine' => $externalEngine ? config('egide.providers.'.$externalEngine['provider']) : null,
            'labEngine' => $engine ? config('egide.providers.'.$engine['provider']) : null,
            'initialAgent' => $request->boolean('agent'),
            'initial' => $request->query('mode', 'laboratory'),
            'previous' => $previous?->only(['id', 'name', 'target_id', 'budget']),
        ]);
    }

    public function createScan(Request $request)
    {
        $data = $request->validate([
            'mode' => 'required|in:laboratory,retest,external',
            'target_id' => 'nullable|required_if:mode,external|integer',
            'budget' => 'nullable|integer|min:10|max:'.($request->input('mode') === 'external' ? 2000 : 600),
            'authorized' => 'accepted_if:mode,external',
            'agent' => 'sometimes|boolean',
            'retest_of' => 'nullable|uuid|prohibited_unless:mode,external',
        ]);

        if (Cache::get(AdminController::PAUSED)) {
            throw ValidationException::withMessages(['mode' => 'Novas sessões estão pausadas pelo administrador da plataforma.']);
        }

        $workspace = $this->workspace($request);
        $external = $data['mode'] === 'external';
        if ($workspace->demo && $external) {
            throw ValidationException::withMessages(['mode' => 'Na demonstração pública, use o laboratório. Crie uma conta para testar o seu próprio domínio.']);
        }
        if ($workspace->demo && ($limit = Demo::limitReached($workspace))) {
            throw ValidationException::withMessages(['mode' => $limit]);
        }
        $target = $external ? Target::where('user_id', $request->user()->id)
            ->whereNotNull('verified_at')->findOrFail($data['target_id']) : null;

        $missing = 'O motor de IA da plataforma ainda não foi configurado pelo administrador.';
        $engine = $external ? $this->engine($workspace, true) : null;
        if ($external && $engine === null) {
            throw ValidationException::withMessages(['target_id' => $missing]);
        }

        if (! $external && ! empty($data['agent'])) {
            $engine = $this->engine($workspace);
            if ($engine === null) {
                throw ValidationException::withMessages(['agent' => $missing]);
            }
        }
        if ($engine !== null && ! $workspace->demo && ($limit = Engine::limitReached($request->user()))) {
            throw ValidationException::withMessages(['mode' => $limit]);
        }
        $provider = $engine['provider'] ?? 'lab';

        $retestOf = $data['retest_of'] ?? null;
        if ($retestOf !== null && (! isset($target->credentials['b']) || ! Scan::where('user_id', $request->user()->id)
            ->where('target_id', $target->id)->where('mode', 'external')->where('status', 'completed')
            ->where('result', 'exposure')->whereKey($retestOf)->exists())) {
            throw ValidationException::withMessages(['target_id' => 'O reteste exige um achado anterior deste ambiente e duas contas de teste.']);
        }

        if ($external && ! Scope::verify($target)) {
            $target->update(['verified_at' => null]);
            throw ValidationException::withMessages(['target_id' => 'Renove a verificação do domínio na página Ambientes.']);
        }

        $variant = $data['mode'] === 'retest' ? 'corrigido' : 'vulneravel';
        $scope = $external ? [...Scope::launch($target), 'retest_of' => $retestOf] : [
            'url' => "http://lab.egide.test:8788/{$variant}", 'lab' => true,
            'rules' => [
                ['method' => 'GET', 'path' => "/{$variant}", 'prefix' => true],
                ['method' => 'GET', 'path' => "/servicos/{$variant}", 'prefix' => true],
                ['method' => 'GET', 'path' => '/favicon.ico', 'prefix' => false],
                ['method' => 'POST', 'path' => "/{$variant}/cadastro", 'prefix' => false],
                ['method' => 'POST', 'path' => "/{$variant}/entrar", 'prefix' => false],
                ['method' => 'POST', 'path' => "/servicos/{$variant}/graphql", 'prefix' => false],
                ['method' => 'POST', 'path' => "/servicos/{$variant}/preferencias", 'prefix' => false],
                ['method' => 'POST', 'path' => "/servicos/{$variant}/resgatar", 'prefix' => false],
                ['method' => 'DELETE', 'path' => "/servicos/{$variant}/reservas", 'prefix' => true],
            ],
            'denied' => ['/administracao', '/pagamentos'],
            'write' => ['method' => 'PATCH', 'host' => 'lab.egide.test', 'path' => "/servicos/{$variant}/extratos", 'prefix' => true, 'max' => 4],
        ];
        $scope['nav_model'] = $engine['nav_model'] ?? null;

        $model = $engine['model'] ?? null;
        $engineKey = $engine['key'] ?? null;
        $create = fn () => DB::transaction(function () use ($request, $data, $target, $scope, $provider, $model, $engineKey) {
            $scan = Scan::create([
                'user_id' => $request->user()->id, 'target_id' => $target?->id,
                'name' => $target?->name ?? ($data['mode'] === 'retest' ? 'Reteste de autorização' : 'Laboratório de autorização'),
                'mode' => $data['mode'], 'scope' => $scope,
                'provider' => $provider,
                'model' => $model,
                'engine_key' => $engineKey,
                'credentials' => $target?->credentials, 'budget' => Scope::budget($data['mode'], $target?->environment_type, (int) ($data['budget'] ?? 80)),
            ]);
            $scan->event('system', 'Sessão recebida', 'Aguardando o executor na fila Horizon.');
            RunScan::dispatch($scan->id)->afterCommit();

            return $scan;
        });
        $user = $request->user();
        $scan = match (true) {
            $workspace->demo => Cache::lock('egide-demo-quota', 10)->block(5, function () use ($workspace, $create) {
                if ($limit = Demo::limitReached($workspace)) {
                    throw ValidationException::withMessages(['mode' => $limit]);
                }

                return $create();
            }),
            $engine !== null && ! $user->is_admin => Cache::lock('egide-ai-quota:'.$user->id, 10)->block(5, function () use ($user, $create) {
                if ($limit = Engine::limitReached($user)) {
                    throw ValidationException::withMessages(['mode' => $limit]);
                }

                return $create();
            }),
            default => $create(),
        };

        return redirect('/sessoes/'.$scan->id);
    }

    public function showScan(Request $request, Scan $scan)
    {
        $this->owns($request, $scan->user_id);

        return Inertia::render('Session', $this->state($scan));
    }

    public function feed(Request $request, Scan $scan)
    {
        $this->owns($request, $scan->user_id);

        return response()->json($this->state($scan))->header('Cache-Control', 'no-store');
    }

    public function frame(Request $request, Scan $scan)
    {
        $this->owns($request, $scan->user_id);
        $path = 'frames/'.$scan->id.'.jpg';
        abort_unless(Storage::exists($path), 404);

        return Storage::response($path, 'sessao.jpg', ['Content-Type' => 'image/jpeg', 'Cache-Control' => 'private, no-store']);
    }

    public function stop(Request $request, Scan $scan)
    {
        $this->owns($request, $scan->user_id);
        Scan::whereKey($scan->id)->whereIn('status', ['queued', 'running'])
            ->whereNull('stop_requested_at')->update(['stop_requested_at' => now()]);

        return back();
    }

    public function findings(Request $request)
    {
        $scans = Scan::where('user_id', $request->user()->id)->select('id');
        $levels = ['critical', 'high', 'medium', 'low'];
        $severity = in_array($request->query('severidade'), $levels, true) ? $request->query('severidade') : 'todas';
        $query = Finding::whereIn('scan_id', $scans)->latest();
        if ($severity !== 'todas') {
            $query->where('severity', $severity);
        }
        $counts = Finding::whereIn('scan_id', $scans)->selectRaw('severity, count(*) as total')->groupBy('severity')->pluck('total', 'severity');

        return Inertia::render('Findings', [
            'findings' => $query->paginate(20)->withQueryString(),
            'severity' => $severity,
            'counts' => ['todas' => (int) $counts->sum()] + collect($levels)->mapWithKeys(fn ($level) => [$level => (int) ($counts[$level] ?? 0)])->all(),
        ]);
    }

    public function report(Request $request, Scan $scan)
    {
        $this->owns($request, $scan->user_id);
        $document = $this->state($scan, full: true);

        return response()->json($document, 200, [
            'Content-Disposition' => 'attachment; filename="egide-'.$scan->id.'.json"',
            'Cache-Control' => 'private, no-store',
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }

    public function printReport(Request $request, Scan $scan)
    {
        $this->owns($request, $scan->user_id);
        $state = $this->state($scan, full: true);

        return Inertia::render('Report', [
            ...$state,
            'target' => $scan->target?->only(['name', 'origin']),
            'engine' => config('egide.providers.'.$scan->provider, $scan->provider),
            'generatedAt' => now()->toIso8601String(),
        ]);
    }

    public function settings(Request $request)
    {
        $workspace = $this->workspace($request);

        return Inertia::render('Settings', [
            'settings' => $workspace->only(['name']),
            'engine' => ($engine = $this->engine($workspace)) ? [
                'label' => config('egide.providers.'.$engine['provider'], $engine['provider']), 'model' => $engine['model'],
            ] : null,
            'usage' => $request->user()->is_admin || $workspace->demo ? null : [
                'used' => Engine::usedToday($request->user()->id), 'limit' => Platform::current()->ai_daily_limit,
            ],
            'hasWebhook' => (bool) $workspace->webhook_url,
            'tokens' => ApiToken::where('user_id', $request->user()->id)->latest()->get(['id', 'name', 'prefix', 'last_used_at', 'created_at']),
            'issuedToken' => $request->session()->get('api_token'),
            'apiBase' => url('/api/v1'),
        ]);
    }

    public function saveSettings(Request $request)
    {
        if ($this->workspace($request)->demo) {
            throw ValidationException::withMessages(['name' => 'As configurações ficam bloqueadas na demonstração pública. Crie uma conta para personalizar o workspace.']);
        }
        $this->workspace($request)->update($request->validate(['name' => 'required|string|max:60']));

        return back()->with('notice', 'Workspace salvo.');
    }

    private function state(Scan $scan, bool $full = false): array
    {
        $events = $scan->events()->latest('id')->when(! $full, fn ($query) => $query->limit(200))->get()->reverse()->values();

        return [
            'scan' => $scan->toArray(), 'events' => $events, 'findings' => $scan->findings()->get(),
            'frame' => Storage::exists('frames/'.$scan->id.'.jpg'),
            'frame_at' => $this->frameAt($scan->id),
        ];
    }

    private function frameAt(int|string $scanId): ?string
    {
        $path = 'frames/'.$scanId.'.jpg';

        return Storage::exists($path) ? Carbon::createFromTimestamp(Storage::lastModified($path))->toIso8601String() : null;
    }

    private function workspace(Request $request): Workspace
    {
        return Workspace::firstOrCreate(['user_id' => $request->user()->id], ['name' => $request->user()->name]);
    }

    private function engine(Workspace $workspace, bool $external = false): ?array
    {
        return $workspace->demo && $external ? null : Engine::platform($external);
    }

    private function owns(Request $request, int $owner): void
    {
        abort_unless($request->user()->id === $owner, 404);
    }
}
