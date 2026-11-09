<?php

namespace App\Sentinel;

use App\Jobs\NotifyAlert;
use App\Models\Alert;
use App\Models\Monitor;
use App\Models\MonitorEvent;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;

final class Detector
{
    public const BRUTE_FORCE = 10;

    public const STUFFING_ACCOUNTS = 5;

    public const TAKEOVER_FAILURES = 5;

    public const DENIED_BURST = 20;

    public const ANOMALY_FLOOR = 10;

    public const RULES = [
        'brute_force' => ['high', 'Força bruta contra o login'],
        'credential_stuffing' => ['high', 'Várias contas testadas pelo mesmo IP'],
        'takeover_suspect' => ['critical', 'Login aceito após sequência de falhas'],
        'denied_burst' => ['medium', 'Rajada de acessos negados'],
        'failure_anomaly' => ['medium', 'Pico anormal de falhas de login'],
    ];

    public function inspect(Monitor $monitor, Collection $events, ?Carbon $now = null): array
    {
        $now ??= now();
        $alerts = [];
        $query = fn () => MonitorEvent::where('monitor_id', $monitor->id);

        foreach ($events->where('type', 'login_failed')->pluck('ip')->unique() as $ip) {
            $failures = $query()->where('type', 'login_failed')->where('ip', $ip)
                ->where('occurred_at', '>=', $now->copy()->subMinutes(5))->count();
            if ($failures >= self::BRUTE_FORCE) {
                $alerts[] = $this->raise($monitor, 'brute_force', $now, $failures,
                    "{$failures} falhas de login do IP {$ip} em 5 minutos.", ip: $ip);
            }
            $accounts = $query()->where('type', 'login_failed')->where('ip', $ip)->whereNotNull('subject')
                ->where('occurred_at', '>=', $now->copy()->subMinutes(10))->distinct()->count('subject');
            if ($accounts >= self::STUFFING_ACCOUNTS) {
                $alerts[] = $this->raise($monitor, 'credential_stuffing', $now, $accounts,
                    "O IP {$ip} tentou {$accounts} contas diferentes em 10 minutos.", ip: $ip);
            }
        }

        foreach ($events->where('type', 'login_succeeded')->whereNotNull('subject') as $event) {
            $failures = $query()->where('type', 'login_failed')->where('subject', $event['subject'])
                ->where('occurred_at', '>=', $now->copy()->subMinutes(15))->count();
            if ($failures >= self::TAKEOVER_FAILURES) {
                $alerts[] = $this->raise($monitor, 'takeover_suspect', $now, $failures,
                    "Uma conta entrou com sucesso pelo IP {$event['ip']} depois de {$failures} falhas em 15 minutos. Confirme com o titular.",
                    ip: $event['ip'], subject: $event['subject']);
            }
        }

        foreach ($events->where('type', 'access_denied')->pluck('ip')->unique() as $ip) {
            $denied = $query()->where('type', 'access_denied')->where('ip', $ip)
                ->where('occurred_at', '>=', $now->copy()->subMinutes(5))->count();
            if ($denied >= self::DENIED_BURST) {
                $alerts[] = $this->raise($monitor, 'denied_burst', $now, $denied,
                    "{$denied} respostas 401/403 para o IP {$ip} em 5 minutos. Pode indicar varredura de rotas ou de IDs.", ip: $ip);
            }
        }

        if ($events->contains('type', 'login_failed')) {
            $anomaly = $this->anomaly($monitor, $now);
            if ($anomaly) {
                $alerts[] = $this->raise($monitor, 'failure_anomaly', $now, $anomaly['current'],
                    "{$anomaly['current']} falhas de login nos últimos 5 minutos. A média das últimas 24 horas é {$anomaly['mean']} a cada 5 minutos.");
            }
        }

        return array_values(array_filter($alerts));
    }

    public function anomaly(Monitor $monitor, Carbon $now): ?array
    {
        $since = $now->copy()->subDay();
        $window = $now->copy()->subMinutes(5);
        $times = MonitorEvent::where('monitor_id', $monitor->id)->where('type', 'login_failed')
            ->where('occurred_at', '>=', $since)->orderByDesc('occurred_at')->limit(50000)->pluck('occurred_at');
        $current = $times->filter(fn ($time) => $time >= $window)->count();
        if ($current < self::ANOMALY_FLOOR) {
            return null;
        }

        $buckets = array_fill(0, 287, 0);
        foreach ($times as $time) {
            if ($time < $window) {
                $index = (int) floor($since->diffInSeconds($time) / 300);
                if ($index >= 0 && $index < 287) {
                    $buckets[$index]++;
                }
            }
        }
        $mean = array_sum($buckets) / count($buckets);
        $deviation = sqrt(array_sum(array_map(fn ($value) => ($value - $mean) ** 2, $buckets)) / count($buckets));
        if ($current <= $mean + 3 * max($deviation, 1)) {
            return null;
        }

        return ['current' => $current, 'mean' => round($mean, 1)];
    }

    private function raise(Monitor $monitor, string $rule, Carbon $now, int $count, string $detail, ?string $ip = null, ?string $subject = null): Alert
    {
        [$severity, $title] = self::RULES[$rule];
        $fingerprint = hash('sha256', $rule.'|'.($ip ?? '').'|'.($subject ?? '').'|'.intdiv($now->timestamp, 3600));
        try {
            $alert = Alert::firstOrCreate(['monitor_id' => $monitor->id, 'fingerprint' => $fingerprint], [
                'rule' => $rule, 'severity' => $severity, 'title' => $title, 'detail' => $detail, 'ip' => $ip,
                'subject' => $subject, 'count' => $count, 'first_seen_at' => $now, 'last_seen_at' => $now,
            ]);
        } catch (UniqueConstraintViolationException) {
            $alert = Alert::where('monitor_id', $monitor->id)->where('fingerprint', $fingerprint)->firstOrFail();
        }
        $isNew = $alert->wasRecentlyCreated;
        $alert->fill([
            'rule' => $rule, 'severity' => $severity, 'title' => $title, 'detail' => $detail,
            'ip' => $ip, 'subject' => $subject, 'count' => max($count, (int) $alert->count),
            'first_seen_at' => $alert->first_seen_at ?? $now, 'last_seen_at' => $now,
            'status' => $isNew ? 'open' : $alert->status,
        ])->save();
        if ($isNew && $monitor->webhook_url) {
            NotifyAlert::dispatch($alert->id);
        }

        return $alert;
    }
}
