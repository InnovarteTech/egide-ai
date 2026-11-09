<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\Monitor;
use App\Models\MonitorEvent;
use App\Sentinel\Webhook;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;

class SentinelController extends Controller
{
    public function index(Request $request)
    {
        $monitors = Monitor::where('user_id', $request->user()->id)
            ->withCount(['alerts as open_alerts' => fn ($query) => $query->where('status', 'open')])
            ->latest()->get();

        return Inertia::render('Monitors', [
            'monitors' => $monitors->map(fn (Monitor $monitor) => [
                ...$monitor->only(['id', 'name', 'key_prefix', 'last_event_at', 'open_alerts', 'created_at']),
                'events_24h' => $monitor->events()->where('occurred_at', '>=', now()->subDay())->count(),
            ]),
        ]);
    }

    public function store(Request $request)
    {
        $data = $request->validate(['name' => 'required|string|max:100']);
        abort_if(Monitor::where('user_id', $request->user()->id)->count() >= 20, 422, 'Limite de monitores atingido.');
        $key = Monitor::issueKey();
        $monitor = Monitor::create([
            'user_id' => $request->user()->id, 'name' => $data['name'],
            'key_hash' => Monitor::hashKey($key), 'key_prefix' => substr($key, 0, 12),
        ]);

        return redirect('/sentinela/'.$monitor->id)->with('monitor_key', $key)
            ->with('notice', 'Monitor criado. Copie a chave agora: ela não será exibida de novo.');
    }

    public function show(Request $request, Monitor $monitor)
    {
        $this->owns($request, $monitor);
        $since = now()->subDay();
        $events = $monitor->events()->where('occurred_at', '>=', $since);

        return Inertia::render('Monitor', [
            'monitor' => [
                ...$monitor->only(['id', 'name', 'key_prefix', 'last_event_at', 'created_at']),
                'has_webhook' => (bool) $monitor->webhook_url,
            ],
            'issuedKey' => $request->session()->get('monitor_key'),
            'endpoint' => url('/api/sentinela/eventos'),
            'stats' => [
                'events' => (clone $events)->count(),
                'failed' => (clone $events)->where('type', 'login_failed')->count(),
                'denied' => (clone $events)->where('type', 'access_denied')->count(),
                'ips' => (clone $events)->distinct()->count('ip'),
                'open' => $monitor->alerts()->where('status', 'open')->count(),
            ],
            'alerts' => $monitor->alerts()->latest('last_seen_at')->limit(50)->get()
                ->map->only(['id', 'rule', 'severity', 'title', 'detail', 'ip', 'count', 'status', 'first_seen_at', 'last_seen_at']),
            'events' => $monitor->events()->latest('occurred_at')->limit(40)->get()
                ->map(fn (MonitorEvent $event) => [
                    ...$event->only(['id', 'type', 'ip', 'path', 'status', 'occurred_at']),
                    'subject' => $event->subject ? substr($event->subject, 0, 10) : null,
                ]),
        ]);
    }

    public function update(Request $request, Monitor $monitor)
    {
        $this->owns($request, $monitor);
        $data = $request->validate(['name' => 'required|string|max:100', 'webhook_url' => 'nullable|string|max:500']);
        $url = trim((string) ($data['webhook_url'] ?? '')) ?: null;
        if (! Webhook::acceptable($url)) {
            throw ValidationException::withMessages(['webhook_url' => 'Use uma URL HTTPS de um domínio público, sem usuário e senha.']);
        }
        $monitor->update(['name' => $data['name'], 'webhook_url' => $url]);

        return back()->with('notice', 'Monitor atualizado.');
    }

    public function rotate(Request $request, Monitor $monitor)
    {
        $this->owns($request, $monitor);
        $key = Monitor::issueKey();
        $monitor->update(['key_hash' => Monitor::hashKey($key), 'key_prefix' => substr($key, 0, 12)]);

        return back()->with('monitor_key', $key)
            ->with('notice', 'Nova chave gerada. A chave anterior parou de funcionar.');
    }

    public function destroy(Request $request, Monitor $monitor)
    {
        $this->owns($request, $monitor);
        $monitor->delete();

        return redirect('/sentinela')->with('notice', 'Monitor removido com os eventos e alertas.');
    }

    public function resolve(Request $request, Alert $alert)
    {
        $this->owns($request, $alert->monitor);
        $alert->update(['status' => $alert->status === 'open' ? 'resolved' : 'open']);

        return back();
    }

    private function owns(Request $request, Monitor $monitor): void
    {
        abort_unless($request->user()->id === $monitor->user_id, 404);
    }
}
