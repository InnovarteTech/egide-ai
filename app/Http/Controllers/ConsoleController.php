<?php

namespace App\Http\Controllers;

use App\Jobs\RunScan;
use App\Models\ApiToken;
use App\Models\Finding;
use App\Models\Scan;
use App\Models\Target;
use App\Models\Workspace;
use App\Security\Demo;
use App\Security\Planner;
use App\Security\Scope;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
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
            'agentAvailable' => $this->agentProvider($this->workspace($request)) !== null,
            'scans' => (clone $scans)->latest()->limit(6)->get(),
            'spotlight' => $spotlight ? [
                ...$spotlight->only(['id', 'name', 'status', 'phase', 'result', 'model', 'request_count', 'budget', 'blocked_count', 'started_at', 'finished_at', 'updated_at']),
                'engine' => config('egide.providers.'.$spotlight->provider, $spotlight->provider),
                'risk' => $spotlight->summary['risk'] ?? null,
                'frame' => Storage::exists('frames/'.$spotlight->id.'.jpg'),
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
            'targets' => Target::where('user_id', $request->user()->id)->latest()->get(),
            'localTargets' => Scope::localEnabled(),
        ]);
    }

    public function createTarget(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string|max:100', 'origin' => 'required|string|max:220',
            'entry_path' => 'required|string|max:180', 'rules' => 'required|string|max:1600',
            'denied' => 'nullable|string|max:800',
            'email_a' => 'nullable|string|max:180|required_with:password_a',
            'password_a' => 'nullable|string|max:200|required_with:email_a',
            'email_b' => 'nullable|string|max:180|required_with:password_b,marker_a,marker_b',
            'password_b' => 'nullable|string|max:200|required_with:email_b',
            'marker_a' => ['nullable', 'required_with:email_b', 'regex:/^(?:EGIDE|ESCOPO)-[A-F0-9]{16}$/D'],
            'marker_b' => ['nullable', 'required_with:email_b', 'different:marker_a', 'regex:/^(?:EGIDE|ESCOPO)-[A-F0-9]{16}$/D'],
            'origin_a' => 'nullable|string|max:220', 'origin_b' => 'nullable|string|max:220',
            'local_port' => 'nullable|integer|min:1|max:65535',
            'record_hint' => 'nullable|string|max:120',
            'path_a' => 'nullable|string|max:250', 'path_b' => 'nullable|string|max:250',
        ]);
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
        $entryPath = $data['entry_path'];
        $rules = Scope::rules($data['rules']);
        $denied = array_values(array_filter(array_map('trim', preg_split('/\R/', $data['denied'] ?? ''))));

        if (! Scope::path($entryPath) || array_filter($denied, fn ($path) => ! Scope::path($path) || $path === '/')) {
            throw ValidationException::withMessages(['entry_path' => 'Use caminhos como /login ou /administracao.']);
        }
        if (! Scope::allows(compact('rules', 'denied'), 'GET', $entryPath)) {
            throw ValidationException::withMessages(['rules' => 'Permita GET no caminho de entrada e retire-o dos bloqueios.']);
        }
        if (Target::where('user_id', $request->user()->id)->where('origin', $origin)->exists()) {
            throw ValidationException::withMessages(['origin' => 'Este domínio já está cadastrado no workspace.']);
        }
        $credentials = [];
        if (! empty($data['email_b']) && (empty($data['email_a']) || strcasecmp($data['email_a'], $data['email_b']) === 0)) {
            throw ValidationException::withMessages(['email_b' => 'Informe duas contas de teste distintas.']);
        }
        foreach (['a', 'b'] as $actor) {
            if (! empty($data['email_'.$actor])) {
                $accountOrigin = empty($data['origin_'.$actor]) ? null : Scope::origin($data['origin_'.$actor]);
                if ($accountOrigin && $localPort === null && Scope::isLocalOrigin($accountOrigin)) {
                    throw ValidationException::withMessages(['origin_'.$actor => 'Subdomínios '.Scope::LOCAL_SUFFIX.' só funcionam no modo local, com a porta informada.']);
                }
                if ($accountOrigin && $localPort !== null && ! Scope::isLocalOrigin($accountOrigin)) {
                    throw ValidationException::withMessages(['origin_'.$actor => 'No modo local, use um subdomínio terminado em '.Scope::LOCAL_SUFFIX.'.']);
                }
                if ($accountOrigin && ! Scope::sibling($origin, $accountOrigin)) {
                    throw ValidationException::withMessages(['origin_'.$actor => 'Use um subdomínio do mesmo domínio do ativo, como https://empresa-a.seuapp.com.br.']);
                }
                $recordPath = $data['path_'.$actor] ?? null;
                if ($recordPath !== null && (! Scope::path($recordPath) || ! Scope::allows(compact('rules', 'denied'), 'GET', $recordPath))) {
                    throw ValidationException::withMessages(['path_'.$actor => 'Use uma rota GET permitida pelas regras, sem parâmetros, como /api/pedidos/123.']);
                }
                $credentials[$actor] = [
                    'email' => $data['email_'.$actor], 'password' => $data['password_'.$actor],
                    'marker' => $data['marker_'.$actor] ?? null, 'origin' => $accountOrigin, 'path' => $recordPath,
                ];
            }
        }

        if (isset($credentials['a']['path'], $credentials['b']['path']) && $credentials['a']['path'] === $credentials['b']['path']
            && ($credentials['a']['origin'] ?? $origin) === ($credentials['b']['origin'] ?? $origin)) {
            throw ValidationException::withMessages(['path_b' => 'Cada conta precisa de um registro com rota própria.']);
        }

        Target::create([
            'user_id' => $request->user()->id, 'name' => $data['name'],
            'origin' => $origin, 'entry_path' => $entryPath,
            'verification_token' => Str::random(48), 'rules' => $rules, 'denied' => $denied,
            'credentials' => $credentials ?: null, 'local_port' => $localPort,
            'record_hint' => isset($data['record_hint']) ? trim($data['record_hint']) : null,
            'verified_at' => $localPort !== null ? now() : null,
        ]);

        return back()->with('notice', $localPort !== null
            ? 'Ativo local cadastrado. O executor acessa a porta '.$localPort.' da sua máquina, sem passar pela internet.'
            : 'Ativo cadastrado. Publique o código para verificar o domínio.');
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
        $provider = $this->agentProvider($workspace);
        $externalProvider = $this->agentProvider($workspace, true);
        $retest = $request->query('retest');
        $previous = is_string($retest) && Str::isUuid($retest) ? Scan::where('user_id', $request->user()->id)
            ->where('mode', 'external')->where('result', 'exposure')->find($retest) : null;
        $targets = Target::where('user_id', $request->user()->id)->whereNotNull('verified_at')->get();

        return Inertia::render('NewSession', [
            'targets' => $targets->map(fn (Target $target) => [
                ...$target->only(['id', 'name', 'origin']), 'comparison' => isset($target->credentials['b']),
            ]),
            'externalEngine' => $externalProvider ? config('egide.providers.'.$externalProvider) : null,
            'labEngine' => $provider ? config('egide.providers.'.$provider) : null,
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
            'budget' => 'nullable|integer|min:10|max:180',
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

        $provider = $external ? $this->agentProvider($workspace, true) : 'lab';
        if ($external && $provider === null) {
            throw ValidationException::withMessages(['target_id' => 'Configure um provedor de IA antes de explorar um ativo verificado.']);
        }

        if (! $external && ! empty($data['agent'])) {
            $provider = $this->agentProvider($workspace);
            if ($provider === null) {
                throw ValidationException::withMessages(['agent' => 'Configure um provedor de IA para executar o laboratório com IA.']);
            }
        }

        $retestOf = $data['retest_of'] ?? null;
        if ($retestOf !== null && (! isset($target->credentials['b']) || ! Scan::where('user_id', $request->user()->id)
            ->where('target_id', $target->id)->where('mode', 'external')->where('status', 'completed')
            ->where('result', 'exposure')->whereKey($retestOf)->exists())) {
            throw ValidationException::withMessages(['target_id' => 'O reteste exige um achado anterior deste ativo e duas contas de teste.']);
        }

        if ($external && ! Scope::verify($target)) {
            $target->update(['verified_at' => null]);
            throw ValidationException::withMessages(['target_id' => 'Renove a verificação do domínio na página Ativos.']);
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
            ],
            'denied' => ['/administracao', '/pagamentos'],
        ];

        $local = $provider === 'lab' || isset(Planner::LOCAL[$provider]);
        $model = $provider === 'claude_local' ? config('egide.claude_model') : ($local ? null : ($workspace->demo ? config('egide.demo_model') : $workspace->model));
        $engineKey = $local ? null : ($workspace->demo ? config('egide.demo_api_key') : $workspace->api_key);
        $create = fn () => DB::transaction(function () use ($request, $data, $target, $scope, $provider, $model, $engineKey) {
            $scan = Scan::create([
                'user_id' => $request->user()->id, 'target_id' => $target?->id,
                'name' => $target?->name ?? ($data['mode'] === 'retest' ? 'Reteste de autorização' : 'Laboratório de autorização'),
                'mode' => $data['mode'], 'scope' => $scope,
                'provider' => $provider,
                'model' => $model,
                'engine_key' => $engineKey,
                'credentials' => $target?->credentials, 'budget' => $data['budget'] ?? 80,
            ]);
            $scan->event('system', 'Sessão recebida', 'Aguardando o executor na fila Horizon.');
            RunScan::dispatch($scan->id)->afterCommit();

            return $scan;
        });
        $scan = ! $workspace->demo ? $create() : Cache::lock('egide-demo-quota', 10)->block(5, function () use ($workspace, $create) {
            if ($limit = Demo::limitReached($workspace)) {
                throw ValidationException::withMessages(['mode' => $limit]);
            }

            return $create();
        });

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
            'settings' => $workspace->only(['name', 'accent', 'provider', 'model']),
            'providers' => collect(config('egide.providers'))->filter(fn ($label, $key) => ! isset(Planner::LOCAL[$key])
                || in_array($key, Planner::availableLocal(), true))->all(),
            'local' => array_keys(Planner::LOCAL),
            'hasKey' => (bool) $workspace->api_key,
            'hasWebhook' => (bool) $workspace->webhook_url,
            'tokens' => ApiToken::where('user_id', $request->user()->id)->latest()->get(['id', 'name', 'prefix', 'last_used_at', 'created_at']),
            'issuedToken' => $request->session()->get('api_token'),
            'apiBase' => url('/api/v1'),
        ]);
    }

    public function saveSettings(Request $request)
    {
        if ($this->workspace($request)->demo) {
            throw ValidationException::withMessages(['provider' => 'As configurações ficam bloqueadas na demonstração pública. Crie uma conta para usar o seu provedor.']);
        }
        $data = $request->validate([
            'name' => 'required|string|max:60', 'accent' => 'required|regex:/^#[0-9a-fA-F]{6}$/',
            'provider' => ['required', Rule::in(array_keys(config('egide.providers')))],
            'model' => 'nullable|string|max:100|regex:/^[a-zA-Z0-9_.:\/-]+$/',
            'api_key' => 'nullable|string|max:450',
        ]);
        $workspace = $this->workspace($request);
        $key = $data['api_key'] ?? ($workspace->provider === $data['provider'] ? $workspace->api_key : null);

        $local = $data['provider'] === 'lab' || isset(Planner::LOCAL[$data['provider']]);
        if (! $local && (! $key || empty($data['model']))) {
            throw ValidationException::withMessages(['api_key' => 'Informe o identificador do modelo e uma chave para esse provedor.']);
        }

        $workspace->update([...$data, 'api_key' => $local ? null : $key, 'model' => $local ? null : ($data['model'] ?? null)]);

        return back()->with('notice', 'Configurações salvas.');
    }

    private function state(Scan $scan, bool $full = false): array
    {
        $events = $scan->events()->latest('id')->when(! $full, fn ($query) => $query->limit(200))->get()->reverse()->values();

        return [
            'scan' => $scan->toArray(), 'events' => $events, 'findings' => $scan->findings()->get(),
            'frame' => Storage::exists('frames/'.$scan->id.'.jpg'),
        ];
    }

    private function workspace(Request $request): Workspace
    {
        return Workspace::firstOrCreate(['user_id' => $request->user()->id], ['name' => $request->user()->name]);
    }

    private function agentProvider(Workspace $workspace, bool $external = false): ?string
    {
        if ($workspace->demo) {
            return $external ? null : Demo::provider();
        }
        if (isset(Planner::LOCAL[$workspace->provider])) {
            return Planner::localProvider($external, $workspace->provider);
        }
        if ($workspace->provider !== 'lab' && $workspace->api_key && $workspace->model) {
            return $workspace->provider;
        }

        return Planner::localProvider($external);
    }

    private function owns(Request $request, int $owner): void
    {
        abort_unless($request->user()->id === $owner, 404);
    }
}
