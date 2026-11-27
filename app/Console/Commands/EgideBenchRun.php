<?php

namespace App\Console\Commands;

use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\User;
use App\Security\Engine;
use App\Security\Scope;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

class EgideBenchRun extends Command
{
    private const FINISHED = ['completed', 'failed', 'cancelled'];

    protected $signature = 'egide:bench:run
        {--pares=1 : Pares de sessões (vulnerável + corrigida) a executar}
        {--usuario= : E-mail do dono das sessões; padrão é o primeiro administrador}
        {--agente : Usa o motor de IA da plataforma em vez do roteiro do laboratório}
        {--orcamento=300 : Orçamento de requisições de cada sessão}
        {--espera=3600 : Tempo máximo de espera, em segundos}
        {--intervalo=10 : Segundos entre as verificações de andamento}
        {--saida= : Grava o relatório JSON neste arquivo}';

    protected $description = 'Executa pares de sessões do laboratório (vulnerável e corrigida) e mede o resultado com egide:bench';

    public function handle(): int
    {
        $pairs = $this->integer('pares', 1, 50);
        $budget = $this->integer('orcamento', 10, 600);
        $wait = $this->integer('espera', 1, 86400);
        $interval = $this->integer('intervalo', 1, 600);
        if (in_array(null, [$pairs, $budget, $wait, $interval], true)) {
            return self::FAILURE;
        }

        $email = $this->option('usuario');
        $user = $email ? User::where('email', $email)->first() : User::where('is_admin', true)->orderBy('id')->first();
        if ($user === null) {
            $this->error($email ? "Usuário {$email} não encontrado." : 'Nenhum administrador encontrado. Rode php artisan db:seed.');

            return self::FAILURE;
        }

        $engine = $this->option('agente') ? Engine::platform() : null;
        if ($this->option('agente') && $engine === null) {
            $this->error('O motor de IA da plataforma ainda não foi configurado no Super admin.');

            return self::FAILURE;
        }

        $ids = [];
        for ($pair = 0; $pair < $pairs; $pair++) {
            foreach (['laboratory' => 'vulneravel', 'retest' => 'corrigido'] as $mode => $variant) {
                $ids[] = $this->launch($user, $mode, $variant, $budget, $engine);
            }
        }
        $this->info(count($ids).' sessões enfileiradas ('.($engine['provider'] ?? 'lab').').');

        $deadline = time() + $wait;
        while (($pending = Scan::whereKey($ids)->whereNotIn('status', self::FINISHED)->count()) > 0) {
            if (time() >= $deadline) {
                $this->error("Tempo esgotado com {$pending} sessões ainda em andamento.");

                return self::FAILURE;
            }
            $this->line("Aguardando {$pending} de ".count($ids).' sessões…');
            sleep($interval);
        }

        $unfinished = Scan::whereKey($ids)->where('status', '!=', 'completed')->pluck('status', 'id');
        foreach ($unfinished as $id => $status) {
            $this->warn("Sessão {$id} terminou como {$status} e fica fora do relatório.");
        }

        Artisan::call('egide:bench', ['--last' => $pairs, '--json' => true, '--sessao' => $ids]);
        $report = trim(Artisan::output());
        if ($path = $this->option('saida')) {
            file_put_contents($path, $report.PHP_EOL);
            $this->info("Relatório gravado em {$path}.");
        } else {
            $this->line($report);
        }

        return $unfinished->count() === count($ids) ? self::FAILURE : self::SUCCESS;
    }

    private function launch(User $user, string $mode, string $variant, int $budget, ?array $engine): string
    {
        return DB::transaction(function () use ($user, $mode, $variant, $budget, $engine) {
            $scan = Scan::create([
                'user_id' => $user->id,
                'name' => $mode === 'retest' ? 'Benchmark · reteste' : 'Benchmark · laboratório',
                'mode' => $mode,
                'scope' => [...Scope::lab($variant), 'nav_model' => $engine['nav_model'] ?? null],
                'provider' => $engine['provider'] ?? 'lab',
                'model' => $engine['model'] ?? null,
                'engine_key' => $engine['key'] ?? null,
                'budget' => Scope::budget($mode, null, $budget),
            ]);
            $scan->event('system', 'Sessão recebida', 'Benchmark: aguardando o executor na fila Horizon.');
            RunScan::dispatch($scan->id)->afterCommit();

            return $scan->id;
        });
    }

    private function integer(string $option, int $min, int $max): ?int
    {
        $value = filter_var($this->option($option), FILTER_VALIDATE_INT, ['options' => ['min_range' => $min, 'max_range' => $max]]);
        if ($value === false) {
            $this->error("Informe --{$option} com um número inteiro entre {$min} e {$max}.");

            return null;
        }

        return $value;
    }
}
