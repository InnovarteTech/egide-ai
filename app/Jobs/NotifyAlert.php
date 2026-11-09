<?php

namespace App\Jobs;

use App\Models\Alert;
use App\Sentinel\Webhook;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class NotifyAlert implements ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public array $backoff = [10, 60];

    public function __construct(public int $alertId) {}

    public function handle(): void
    {
        $alert = Alert::with('monitor')->find($this->alertId);
        $url = $alert?->monitor?->webhook_url;
        if (! $alert || ! $url || $alert->notified_at) {
            return;
        }

        $text = "[Égide AI · Sentinela] {$alert->title} · {$alert->monitor->name}\n{$alert->detail}";
        Webhook::send($url, [
            'text' => $text, 'content' => $text,
            'alert' => [
                'id' => $alert->id, 'rule' => $alert->rule, 'severity' => $alert->severity,
                'title' => $alert->title, 'detail' => $alert->detail, 'ip' => $alert->ip,
                'count' => $alert->count, 'monitor' => $alert->monitor->name,
                'first_seen_at' => $alert->first_seen_at->toIso8601String(),
            ],
        ]);
        $alert->update(['notified_at' => now()]);
    }
}
