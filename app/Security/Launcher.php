<?php

namespace App\Security;

use App\Http\Controllers\AdminController;
use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\Target;
use App\Models\Workspace;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use RuntimeException;

final class Launcher
{
    public const TRIGGERS = ['manual', 'schedule', 'api'];

    public static function provider(Workspace $workspace, bool $external = false): ?string
    {
        if (isset(Planner::LOCAL[$workspace->provider])) {
            return Planner::localProvider($external, $workspace->provider);
        }
        if ($workspace->provider !== 'lab' && $workspace->api_key && $workspace->model) {
            return $workspace->provider;
        }

        return null;
    }

    public function external(Target $target, string $trigger, int $budget = 80): Scan
    {
        if (! in_array($trigger, self::TRIGGERS, true)) {
            throw new RuntimeException('Origem da sessão inválida.');
        }
        if (Cache::get(AdminController::PAUSED)) {
            throw new RuntimeException('Novas sessões estão pausadas pelo administrador da plataforma.');
        }
        if ($target->user?->suspended_at) {
            throw new RuntimeException('A conta dona deste ativo está suspensa.');
        }
        if (! $target->verified_at) {
            throw new RuntimeException('O ativo precisa estar verificado.');
        }
        if (Scan::where('target_id', $target->id)->whereIn('status', ['queued', 'running'])->exists()) {
            throw new RuntimeException('Já existe uma sessão em andamento para este ativo.');
        }

        $workspace = Workspace::firstOrCreate(['user_id' => $target->user_id], ['name' => 'Meu workspace']);
        $provider = self::provider($workspace, true);
        if ($provider === null) {
            throw new RuntimeException('Configure um provedor de IA no workspace.');
        }
        if (! Scope::verify($target)) {
            $target->update(['verified_at' => null]);
            throw new RuntimeException('A verificação do domínio expirou. Renove na página Ativos.');
        }

        $local = isset(Planner::LOCAL[$provider]);

        return DB::transaction(function () use ($target, $trigger, $budget, $workspace, $provider, $local) {
            $scan = Scan::create([
                'user_id' => $target->user_id, 'target_id' => $target->id, 'name' => $target->name,
                'mode' => 'external', 'trigger' => $trigger,
                'scope' => [...Scope::launch($target), 'retest_of' => null],
                'provider' => $provider,
                'model' => $provider === 'claude_local' ? config('egide.claude_model') : ($local ? null : $workspace->model),
                'engine_key' => $local ? null : $workspace->api_key,
                'credentials' => $target->credentials, 'budget' => max(10, min(180, $budget)),
            ]);
            $origin = ['schedule' => 'agendamento', 'api' => 'integração via API', 'manual' => 'console'][$trigger];
            $scan->event('system', 'Sessão recebida', "Iniciada por {$origin}. Aguardando o executor na fila Horizon.");
            RunScan::dispatch($scan->id)->afterCommit();

            return $scan;
        });
    }
}
