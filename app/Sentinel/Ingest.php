<?php

namespace App\Sentinel;

use App\Models\Monitor;
use App\Models\MonitorEvent;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

final class Ingest
{
    public function __construct(private Detector $detector) {}

    public function accept(Monitor $monitor, array $events, ?Carbon $now = null): array
    {
        $now ??= now();
        $rows = [];
        foreach (array_values($events) as $index => $event) {
            $type = $event['type'] ?? null;
            $ip = $event['ip'] ?? null;
            $subject = $event['subject'] ?? null;
            $path = $event['path'] ?? null;
            $status = $event['status'] ?? null;
            if (! in_array($type, MonitorEvent::TYPES, true) || ! is_string($ip) || ! filter_var($ip, FILTER_VALIDATE_IP)) {
                throw ValidationException::withMessages(["events.{$index}" => 'Informe type válido e o IP de origem.']);
            }
            if ($subject !== null && (! is_string($subject) || ! preg_match('/^[a-f0-9]{64}$/D', $subject))) {
                throw ValidationException::withMessages(["events.{$index}.subject" => 'Envie o identificador do usuário como hash SHA-256 em hexadecimal. Nunca envie e-mail ou nome.']);
            }
            if ($status !== null && (! is_int($status) || $status < 100 || $status > 599)) {
                throw ValidationException::withMessages(["events.{$index}.status" => 'Status HTTP inválido.']);
            }
            $path = is_string($path) ? mb_substr(strtok($path, '?#') ?: '/', 0, 255) : null;
            $rows[] = [
                'monitor_id' => $monitor->id, 'type' => $type, 'ip' => $ip, 'subject' => $subject,
                'path' => $path, 'status' => $status, 'occurred_at' => $now,
            ];
        }

        DB::transaction(function () use ($monitor, $rows, $now): void {
            foreach (array_chunk($rows, 50) as $chunk) {
                MonitorEvent::insert($chunk);
            }
            $monitor->forceFill(['last_event_at' => $now])->save();
        });

        $alerts = $this->detector->inspect($monitor, collect($rows), $now);

        return ['accepted' => count($rows), 'alerts' => count($alerts)];
    }
}
