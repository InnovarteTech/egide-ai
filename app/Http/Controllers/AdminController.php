<?php

namespace App\Http\Controllers;

use App\Models\Finding;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Inertia\Inertia;

class AdminController extends Controller
{
    public const PAUSED = 'egide.sessions_paused';

    public function index()
    {
        $active = Scan::whereIn('status', ['queued', 'running']);

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
        ]);
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
