<?php

namespace App\Jobs;

use App\Models\Scan;
use App\Models\Workspace;
use App\Sentinel\Webhook;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class NotifyScan implements ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public array $backoff = [10, 60];

    public function __construct(public string $scanId, public array $newFindings = []) {}

    public function handle(): void
    {
        $scan = Scan::find($this->scanId);
        $url = $scan ? Workspace::where('user_id', $scan->user_id)->first()?->webhook_url : null;
        if (! $scan || ! $url) {
            return;
        }

        Webhook::send($url, $this->payload($scan));
    }

    public function payload(Scan $scan): array
    {
        $findings = $scan->findings()->achados()->get();
        $counts = $findings->countBy('severity');
        $risk = $scan->summary['risk'] ?? null;
        $text = '[Égide AI] '.$scan->name.' · '.($scan->regression ? 'REGRESSÃO: ' : '')
            .($scan->status === 'completed' ? 'sessão concluída' : 'sessão interrompida')
            .($risk ? ' · risco '.$risk : '').' · '.$findings->count().' achado(s)';

        return [
            'text' => $text, 'content' => $text,
            'scan' => [
                'id' => $scan->id, 'name' => $scan->name, 'status' => $scan->status, 'result' => $scan->result,
                'trigger' => $scan->trigger, 'regression' => $scan->regression, 'risk' => $risk,
                'findings' => ['critical' => $counts['critical'] ?? 0, 'high' => $counts['high'] ?? 0, 'medium' => $counts['medium'] ?? 0, 'low' => $counts['low'] ?? 0],
                'new_findings' => $this->newFindings,
                'report_url' => url('/sessoes/'.$scan->id.'/relatorio/imprimir'),
            ],
        ];
    }
}
