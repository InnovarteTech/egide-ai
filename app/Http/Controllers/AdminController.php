<?php

namespace App\Http\Controllers;

use App\Models\Finding;
use App\Models\Platform;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Security\Engine;
use App\Security\Planner;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use RuntimeException;

class AdminController extends Controller
{
    public const PAUSED = 'egide.sessions_paused';

    public function index()
    {
        $active = Scan::whereIn('status', ['queued', 'running']);
        $platform = Platform::current();

        return Inertia::render('Admin', [
            'paused' => (bool) Cache::get(self::PAUSED),
            'stats' => [
                'users' => User::count(),
                'targets' => Target::whereNotNull('verified_at')->count(),
                'sessions' => Scan::count(),
                'active' => (clone $active)->count(),
                'blocked' => (int) Scan::sum('blocked_count'),
                'severity' => Finding::selectRaw('severity, count(*) as total')->groupBy('severity')->pluck('total', 'severity'),
            ],
            'active' => $this->withOwner((clone $active)->latest()->get()),
            'recent' => $this->withOwner(Scan::latest()->limit(15)->get()),
            'users' => User::withCount(['scans', 'targets'])->orderBy('id')->get()
                ->map(fn (User $user) => [
                    ...$user->only(['id', 'name', 'email', 'is_admin', 'suspended_at', 'created_at', 'scans_count', 'targets_count']),
                    'findings' => Finding::whereIn('scan_id', Scan::where('user_id', $user->id)->select('id'))->count(),
                ]),
            'horizon' => true,
            'engine' => [
                'provider' => $platform->ai_provider, 'model' => $platform->ai_model, 'nav_model' => $platform->ai_nav_model,
                'keyHint' => filled($key = $platform->key()) ? '…'.mb_substr($key, -4) : null,
                'limit' => $platform->ai_daily_limit, 'ready' => Engine::platform() !== null,
                'providers' => Engine::providers(), 'hosted' => Engine::HOSTED,
            ],
        ]);
    }

    public function saveEngine(Request $request)
    {
        $data = $this->engineInput($request, true);
        $hosted = in_array($data['provider'], Engine::HOSTED, true);
        Platform::current()->update([
            'ai_provider' => $data['provider'],
            'ai_model' => $data['provider'] === 'lab' ? null : $data['model'],
            'ai_nav_model' => $data['provider'] === 'lab' ? null : ($data['nav_model'] ?: null),
            'ai_key' => $hosted ? $data['key'] : null,
            'ai_daily_limit' => $data['daily_limit'],
        ]);

        return back()->with('notice', $data['provider'] === 'lab'
            ? 'Motor de IA desligado. As sessões usam o roteiro do laboratório.'
            : 'Motor de IA da plataforma salvo.');
    }

    public function testEngine(Request $request, Planner $planner)
    {
        $data = $this->engineInput($request, false);
        if ($data['provider'] === 'lab') {
            throw ValidationException::withMessages(['provider' => 'Escolha um provedor de IA para testar.']);
        }
        $field = in_array($data['provider'], Engine::HOSTED, true) ? 'api_key' : 'provider';
        try {
            $planner->check($data['provider'], $data['model'], $data['key']);
            if (filled($data['nav_model'])) {
                $planner->check($data['provider'], $data['nav_model'], $data['key']);
            }
        } catch (ConnectionException) {
            throw ValidationException::withMessages([$field => 'Não foi possível conectar ao provedor: tempo esgotado ou rede bloqueada.']);
        } catch (RuntimeException $exception) {
            throw ValidationException::withMessages([$field => $exception->getMessage()]);
        }

        return back()->with('notice', 'Conexão confirmada: '.config('egide.providers.'.$data['provider']).' respondeu.');
    }

    public function stopAll()
    {
        $stopped = Scan::whereIn('status', ['queued', 'running'])->whereNull('stop_requested_at')
            ->update(['stop_requested_at' => now()]);

        return back()->with('notice', $stopped ? "Parada solicitada para {$stopped} sessão(ões)." : 'Nenhuma sessão ativa.');
    }

    public function stop(Scan $scan)
    {
        Scan::whereKey($scan->id)->whereIn('status', ['queued', 'running'])
            ->whereNull('stop_requested_at')->update(['stop_requested_at' => now()]);

        return back()->with('notice', 'Parada solicitada.');
    }

    public function pause(Request $request)
    {
        $paused = $request->boolean('paused');
        $paused ? Cache::forever(self::PAUSED, true) : Cache::forget(self::PAUSED);

        return back()->with('notice', $paused ? 'Novas sessões pausadas em toda a plataforma.' : 'Novas sessões liberadas.');
    }

    public function suspend(Request $request, User $user)
    {
        abort_if($user->id === $request->user()->id, 422, 'Não é possível suspender a própria conta.');
        $suspend = $request->boolean('suspended');
        $user->forceFill(['suspended_at' => $suspend ? now() : null])->save();
        if ($suspend) {
            Scan::where('user_id', $user->id)->whereIn('status', ['queued', 'running'])
                ->whereNull('stop_requested_at')->update(['stop_requested_at' => now()]);
        }

        return back()->with('notice', $suspend ? 'Conta suspensa e sessões encerradas.' : 'Conta reativada.');
    }

    private function engineInput(Request $request, bool $saving): array
    {
        $data = $request->validate([
            'provider' => ['required', Rule::in(array_keys(Engine::providers()))],
            'model' => 'nullable|string|max:100|regex:/^[a-zA-Z0-9_.:\/-]+$/',
            'nav_model' => 'nullable|string|max:100|regex:/^[a-zA-Z0-9_.:\/-]+$/',
            'api_key' => 'nullable|string|max:450',
            'daily_limit' => [$saving ? 'required' : 'nullable', 'integer', 'min:1', 'max:500'],
        ]);
        $platform = Platform::current();
        $data['model'] ??= null;
        $data['nav_model'] ??= null;
        $data['key'] = $data['api_key'] ?? ($platform->ai_provider === $data['provider'] ? $platform->key() : null);
        if (in_array($data['provider'], Engine::HOSTED, true)) {
            $errors = array_filter([
                'model' => blank($data['model']) ? 'Informe o identificador do modelo.' : null,
                'api_key' => blank($data['key']) ? 'Informe a chave de API desse provedor.' : null,
            ]);
            if ($errors) {
                throw ValidationException::withMessages($errors);
            }
        }

        return $data;
    }

    private function withOwner($scans)
    {
        $owners = User::whereIn('id', $scans->pluck('user_id')->unique())->pluck('email', 'id');

        return $scans->map(fn (Scan $scan) => [
            ...$scan->only(['id', 'name', 'mode', 'status', 'result', 'phase', 'provider', 'request_count', 'budget', 'blocked_count', 'created_at']),
            'host' => parse_url($scan->scope['url'] ?? '', PHP_URL_HOST),
            'owner' => $owners[$scan->user_id] ?? '—',
        ]);
    }
}
