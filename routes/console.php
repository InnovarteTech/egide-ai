<?php

use App\Models\Alert;
use App\Models\Monitor;
use App\Models\MonitorEvent;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Models\Workspace;
use App\Security\Launcher;
use App\Sentinel\Ingest;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;
use Illuminate\Support\Facades\Storage;

Artisan::command('egide:sentinela-retencao {--dias=30}', function () {
    $limit = now()->subDays(max(1, (int) $this->option('dias')));
    $events = MonitorEvent::where('occurred_at', '<', $limit)->delete();
    $alerts = Alert::where('status', 'resolved')->where('last_seen_at', '<', $limit)->delete();
    $this->info("{$events} evento(s) e {$alerts} alerta(s) resolvido(s) removidos.");
})->purpose('Remove eventos do Sentinela fora do prazo de retenção');

Artisan::command('egide:sentinela-demo {monitor}', function (Ingest $ingest) {
    abort_unless(app()->environment('local'), 403, 'A demonstração só roda em ambiente local.');
    $monitor = Monitor::findOrFail($this->argument('monitor'));
    $subject = fn (string $user) => hash_hmac('sha256', $user, 'demo');

    $normal = [];
    foreach (range(1, 12) as $index) {
        $ip = '203.0.113.'.$index;
        $normal[] = ['type' => 'login_succeeded', 'ip' => $ip, 'path' => '/login', 'status' => 200, 'subject' => $subject("cliente{$index}@demo")];
        if ($index % 4 === 0) {
            $normal[] = ['type' => 'login_failed', 'ip' => $ip, 'path' => '/login', 'status' => 401, 'subject' => $subject("cliente{$index}@demo")];
        }
    }
    $ingest->accept($monitor, $normal);
    $this->line('Tráfego normal enviado.');

    $ingest->accept($monitor, array_fill(0, 14, ['type' => 'login_failed', 'ip' => '198.51.100.23', 'path' => '/login', 'status' => 401, 'subject' => $subject('gerente@demo')]));
    $this->line('Simulado: tentativas repetidas contra uma conta.');

    $ingest->accept($monitor, array_map(fn ($index) => ['type' => 'login_failed', 'ip' => '192.0.2.88', 'path' => '/login', 'status' => 401, 'subject' => $subject("lista{$index}@demo")], range(1, 8)));
    $this->line('Simulado: várias contas tentadas pelo mesmo IP.');

    $ingest->accept($monitor, [['type' => 'login_succeeded', 'ip' => '198.51.100.23', 'path' => '/login', 'status' => 200, 'subject' => $subject('gerente@demo')]]);
    $this->line('Simulado: login aceito após sequência de falhas.');

    $ingest->accept($monitor, array_map(fn ($index) => ['type' => 'access_denied', 'ip' => '192.0.2.140', 'path' => '/api/pedidos/'.(1000 + $index), 'status' => 403], range(1, 22)));
    $this->line('Simulado: rajada de acessos negados.');

    $this->info($monitor->alerts()->where('status', 'open')->count().' alerta(s) aberto(s) no monitor '.$monitor->name.'.');
})->purpose('Gera tráfego sintético em um monitor local para demonstração');

Artisan::command('egide:agendadas', function (Launcher $launcher) {
    $due = Target::whereNotNull('verified_at')->whereIn('schedule', ['daily', 'weekly'])
        ->where(fn ($query) => $query->whereNull('next_run_at')->orWhere('next_run_at', '<=', now()))->get();
    foreach ($due as $target) {
        try {
            $scan = $launcher->external($target, 'schedule');
            $target->update(['next_run_at' => now()->add($target->schedule === 'weekly' ? '7 days' : '1 day')]);
            $this->line("{$target->name}: sessão {$scan->id} na fila.");
        } catch (RuntimeException $error) {
            $target->update(['next_run_at' => now()->addHour()]);
            $this->warn("{$target->name}: {$error->getMessage()} Nova tentativa em 1 hora.");
        }
    }
    $this->info($due->count().' ativo(s) avaliados.');
})->purpose('Dispara as sessões agendadas dos ativos verificados');

Artisan::command('egide:demo-limpeza', function () {
    $limit = now()->subHours(max(1, (int) config('egide.demo_ttl_hours')));
    $removed = 0;
    User::whereIn('id', Workspace::where('demo', true)->select('user_id'))
        ->where('created_at', '<', $limit)->where('is_admin', false)
        ->whereNotIn('id', Scan::whereIn('status', ['queued', 'running'])->select('user_id'))
        ->chunkById(200, function ($users) use (&$removed) {
            foreach ($users as $user) {
                foreach (Scan::where('user_id', $user->id)->pluck('id') as $scan) {
                    Storage::delete('frames/'.$scan.'.jpg');
                }
                $user->delete();
                $removed++;
            }
        });
    $this->info($removed.' conta(s) de demonstração removida(s).');
})->purpose('Remove contas da demonstração pública depois do prazo');

Schedule::command('egide:sentinela-retencao')->dailyAt('03:17');
Schedule::command('egide:demo-limpeza')->hourly();

Artisan::command('egide:sessoes-presas', function () {
    $stuck = Scan::where(fn ($query) => $query->where('status', 'running')->where('started_at', '<', now()->subMinutes(15)))
        ->orWhere(fn ($query) => $query->where('status', 'queued')->where('created_at', '<', now()->subMinutes(50)))->get();
    foreach ($stuck as $scan) {
        $scan->update(['status' => 'failed', 'phase' => 'Interrompida', 'finished_at' => now(), 'engine_key' => null, 'credentials' => null,
            'error' => 'A sessão parou de responder e foi encerrada automaticamente. Inicie uma nova sessão.']);
        $scan->event('error', 'Sessão encerrada automaticamente', 'O executor não concluiu a sessão no tempo esperado.');
    }
    $this->info($stuck->count().' sessão(ões) presa(s) encerrada(s).');
})->purpose('Encerra sessões que pararam de responder depois de uma queda');

Schedule::command('egide:sessoes-presas')->everyFiveMinutes();
Schedule::command('egide:agendadas')->everyFifteenMinutes()->withoutOverlapping();
