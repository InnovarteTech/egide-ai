<?php

namespace App\Console\Commands;

use App\Jobs\RunScan;
use App\Models\Platform;
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
        {--concorrencia= : Lança N sessões do laboratório de uma vez e mede o tempo de fila (ignora pares e gabarito)}
        {--usuario= : E-mail do dono das sessões; padrão é o primeiro administrador}
        {--agente : Usa o motor de IA da plataforma em vez do roteiro do laboratório}
        {--provedores= : Matriz de provedores separada por vírgula (ex.: lab,anthropic,openai); substitui --agente}
        {--modelo= : Modelo a usar nos provedores hospedados; padrão é o modelo configurado no Super admin}
        {--orcamento=300 : Orçamento de requisições de cada sessão}
        {--espera=3600 : Tempo máximo de espera, em segundos}
        {--intervalo=10 : Segundos entre as verificações de andamento}
        {--saida= : Grava o relatório JSON neste arquivo}
        {--gabarito= : JSON com as falhas plantadas esperadas; padrão tests/fixtures/lab-gabarito.json quando existir}
        {--min= : Fração mínima do gabarito detectada para aprovar o benchmark}';

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

        $concurrency = filter_var($this->option('concorrencia'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 50]]);
        if ($this->option('concorrencia') !== null && $concurrency === false) {
            $this->error('Informe --concorrencia com um número inteiro entre 1 e 50.');

            return self::FAILURE;
        }

        $engines = $this->engines();
        if ($engines === null) {
            return self::FAILURE;
        }
        if ($concurrency !== false) {
            return $this->concurrency($user, $concurrency, $budget, $wait, $interval, reset($engines));
        }

        $groups = [];
        foreach ($engines as $name => $engine) {
            $groups[$name] = [];
            for ($pair = 0; $pair < $pairs; $pair++) {
                foreach (['laboratory' => 'vulneravel', 'retest' => 'corrigido'] as $mode => $variant) {
                    $groups[$name][] = $this->launch($user, $mode, $variant, $budget, $engine);
                }
            }
        }
        $ids = collect($groups)->flatten()->all();
        $this->info(count($ids).' sessões enfileiradas ('.implode(', ', array_keys($groups)).').');

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

        $gabarito = $this->option('gabarito');
        if (! is_string($gabarito) || $gabarito === '') {
            $default = base_path('tests/fixtures/lab-gabarito.json');
            $gabarito = is_file($default) ? $default : null;
        }
        $options = array_filter([
            '--last' => $pairs, '--json' => true,
            '--gabarito' => $gabarito, '--min' => $this->option('min'),
        ], fn ($value) => $value !== null);
        $code = self::SUCCESS;
        if (count($groups) === 1) {
            $code = Artisan::call('egide:bench', [...$options, '--sessao' => $ids]);
            $report = trim(Artisan::output());
        } else {
            $matrix = [];
            foreach ($groups as $name => $groupIds) {
                $groupCode = Artisan::call('egide:bench', [...$options, '--sessao' => $groupIds]);
                $code = $groupCode !== self::SUCCESS ? $groupCode : $code;
                $matrix[$name] = json_decode(trim(Artisan::output()), true);
            }
            $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION;
            $report = json_encode(['matriz' => $matrix, 'sessoes' => collect($matrix)->flatMap(fn ($item) => $item['sessoes'] ?? [])->all()], $flags);
        }
        if ($path = $this->option('saida')) {
            file_put_contents($path, $report.PHP_EOL);
            $this->info("Relatório gravado em {$path}.");
        } else {
            $this->line($report);
        }

        return $code !== self::SUCCESS || $unfinished->count() === count($ids) ? self::FAILURE : self::SUCCESS;
    }

    private function concurrency(User $user, int $count, int $budget, int $wait, int $interval, ?array $engine): int
    {
        $queuedAt = microtime(true);
        $ids = [];
        for ($i = 0; $i < $count; $i++) {
            $ids[] = $this->launch($user, 'laboratory', 'vulneravel', $budget, $engine);
        }
        $this->info("{$count} sessões simultâneas enfileiradas (".($engine['provider'] ?? 'lab').').');

        $deadline = time() + $wait;
        while (($pending = Scan::whereKey($ids)->whereNotIn('status', self::FINISHED)->count()) > 0) {
            if (time() >= $deadline) {
                $this->error("Tempo esgotado com {$pending} sessões ainda em andamento.");

                return self::FAILURE;
            }
            $this->line("Aguardando {$pending} de {$count} sessões…");
            sleep($interval);
        }

        $scans = Scan::whereKey($ids)->get();
        $rows = $scans->map(fn (Scan $scan) => [
            'id' => $scan->id,
            'status' => $scan->status,
            'fila_s' => $scan->started_at ? max(0, $scan->started_at->getTimestamp() - $scan->created_at->getTimestamp()) : null,
            'duracao_s' => $scan->started_at && $scan->finished_at ? max(0, $scan->finished_at->getTimestamp() - $scan->started_at->getTimestamp()) : null,
            'requisicoes' => (int) $scan->request_count,
        ])->all();
        $queue = collect($rows)->pluck('fila_s')->filter(fn ($v) => $v !== null);
        $report = [
            'concorrencia' => $count,
            'provedor' => $engine['provider'] ?? 'lab',
            'duracao_total_s' => round(microtime(true) - $queuedAt, 1),
            'fila_media_s' => $queue->isEmpty() ? null : round($queue->avg(), 1),
            'fila_max_s' => $queue->isEmpty() ? null : $queue->max(),
            'concluidas' => $scans->where('status', 'completed')->count(),
            'sessoes' => $rows,
        ];
        $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION;
        $report = json_encode($report, $flags);
        if ($path = $this->option('saida')) {
            file_put_contents($path, $report.PHP_EOL);
            $this->info("Relatório gravado em {$path}.");
        } else {
            $this->line($report);
        }

        return $scans->where('status', 'completed')->isNotEmpty() ? self::SUCCESS : self::FAILURE;
    }

    private function engines(): ?array
    {
        $list = $this->option('provedores');
        if (! is_string($list) || trim($list) === '') {
            if (! $this->option('agente')) {
                return ['lab' => null];
            }
            $engine = Engine::platform();
            if ($engine === null) {
                $this->error('O motor de IA da plataforma ainda não foi configurado no Super admin.');

                return null;
            }

            return [$engine['provider'] => $engine];
        }
        $model = $this->option('modelo');
        $platform = Platform::current();
        $engines = [];
        foreach (array_filter(array_map('trim', explode(',', $list))) as $provider) {
            if ($provider === 'lab') {
                $engines['lab'] = null;

                continue;
            }
            if (! in_array($provider, Engine::HOSTED, true)) {
                $this->error("Provedor desconhecido: {$provider}. Use lab ou um de: ".implode(', ', Engine::HOSTED).'.');

                return null;
            }
            $key = env('EGIDE_BENCH_'.strtoupper($provider).'_KEY') ?: ($platform->ai_provider === $provider ? $platform->key() : null);
            if (! $key) {
                $this->error("Sem chave para {$provider}: configure-a no Super admin como provedor atual ou defina EGIDE_BENCH_".strtoupper($provider).'_KEY.');

                return null;
            }
            $engines[$provider] = [
                'provider' => $provider,
                'model' => is_string($model) && $model !== '' ? $model : $platform->ai_model,
                'nav_model' => $platform->ai_nav_model ?: null,
                'key' => $key,
            ];
        }

        return $engines;
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
