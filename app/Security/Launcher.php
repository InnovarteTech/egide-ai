<?php

namespace App\Security;

use App\Http\Controllers\AdminController;
use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\Target;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use RuntimeException;

final class Launcher
{
    public const TRIGGERS = ['manual', 'schedule', 'api'];

    public function external(Target $target, string $trigger, int $budget = 80): Scan
    {
        if (! in_array($trigger, self::TRIGGERS, true)) {
            throw new RuntimeException('Origem da sessão inválida.');
        }
        if (Cache::get(AdminController::PAUSED)) {
            throw new RuntimeException('Novas sessões estão pausadas pelo administrador da plataforma.');
        }
        if ($target->user?->suspended_at) {
            throw new RuntimeException('A conta dona deste ambiente está suspensa.');
        }
        if (! $target->verified_at) {
            throw new RuntimeException('O ambiente precisa estar verificado.');
        }
        if (Scan::where('target_id', $target->id)->whereIn('status', ['queued', 'running'])->exists()) {
            throw new RuntimeException('Já existe uma sessão em andamento para este ambiente.');
        }

        $engine = Engine::platform(true);
        if ($engine === null) {
            throw new RuntimeException('O motor de IA da plataforma ainda não foi configurado pelo administrador.');
        }
        if ($target->user && ($limit = Engine::limitReached($target->user))) {
            throw new RuntimeException($limit);
        }
        if (! Scope::verify($target)) {
            $target->update(['verified_at' => null]);
            throw new RuntimeException('A verificação do domínio expirou. Renove na página Ambientes.');
        }

        return DB::transaction(function () use ($target, $trigger, $budget, $engine) {
            $scan = Scan::create([
                'user_id' => $target->user_id, 'target_id' => $target->id, 'name' => $target->name,
                'mode' => 'external', 'trigger' => $trigger,
                'scope' => [...Scope::launch($target), 'retest_of' => null, 'nav_model' => $engine['nav_model'] ?? null],
                'provider' => $engine['provider'],
                'model' => $engine['model'],
                'engine_key' => $engine['key'],
                'credentials' => $target->credentials, 'budget' => Scope::budget('external', $target->environment_type, $budget),
            ]);
            $origin = ['schedule' => 'agendamento', 'api' => 'integração via API', 'manual' => 'console'][$trigger];
            $scan->event('system', 'Sessão recebida', "Iniciada por {$origin}. Aguardando o executor na fila Horizon.");
            RunScan::dispatch($scan->id)->afterCommit();

            return $scan;
        });
    }
}
