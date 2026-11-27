<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\ResolvesBenchEngines;
use App\Jobs\RunScan;
use App\Models\Scan;
use App\Models\Target;
use App\Models\User;
use App\Security\Scope;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

class EgideBenchAlvos extends Command
{
    use ResolvesBenchEngines;

    private const FINISHED = ['completed', 'failed', 'cancelled'];

    protected $signature = 'egide:bench:alvos
        {--alvos=bench/alvos.json : JSON com a lista de alvos locais (nome, origem, porta, gabarito)}
        {--usuario= : E-mail do dono das sessões; padrão é o primeiro administrador}
        {--agente : Usa o motor de IA da plataforma em vez do roteiro do laboratório}
        {--provedores= : Matriz de provedores separada por vírgula (ex.: lab,anthropic,openai); substitui --agente}
        {--modelo= : Modelo a usar nos provedores hospedados; padrão é o modelo configurado no Super admin}
        {--orcamento=2000 : Orçamento de requisições de cada sessão}
        {--espera=7200 : Tempo máximo de espera, em segundos}
        {--intervalo=15 : Segundos entre as verificações de andamento}
        {--saida= : Grava o relatório JSON neste arquivo}
        {--min= : Fração mínima do gabarito detectada para aprovar o benchmark}';

    protected $description = 'Mede detecção e falsos positivos em alvos locais reais (Juice Shop, VAmPI, DVWA…) via gabaritos por alvo';

    public function handle(): int
    {
        if (! Scope::localEnabled()) {
            $this->error('Alvos locais desabilitados. Defina EGIDE_LOCAL_TARGETS=1 e EGIDE_RUNNER_LOCAL=1 (app local).');

            return self::FAILURE;
        }

        $budget = $this->integer('orcamento', 10, 2000);
        $wait = $this->integer('espera', 1, 86400);
        $interval = $this->integer('intervalo', 1, 600);
        if (in_array(null, [$budget, $wait, $interval], true)) {
            return self::FAILURE;
        }

        $alvos = $this->alvos();
        if ($alvos === null) {
            return self::FAILURE;
        }

        $email = $this->option('usuario');
        $user = $email ? User::where('email', $email)->first() : User::where('is_admin', true)->orderBy('id')->first();
        if ($user === null) {
            $this->error($email ? "Usuário {$email} não encontrado." : 'Nenhum administrador encontrado. Rode php artisan db:seed.');

            return self::FAILURE;
        }

        $engines = $this->engines();
        if ($engines === null) {
            return self::FAILURE;
        }

        $groups = [];
        foreach ($engines as $name => $engine) {
            $groups[$name] = [];
            foreach ($alvos as $alvo) {
                $groups[$name][$alvo['nome']] = $this->launch($user, $alvo, $budget, $engine);
            }
        }
        $ids = collect($groups)->flatMap(fn ($alvos) => array_values($alvos))->all();
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

        $min = $this->option('min');
        $options = ['--modo' => 'external', '--last' => count($alvos) * count($engines), '--json' => true];
        if (is_string($min) && $min !== '') {
            $options['--min'] = $min;
        }
        $matrix = [];
        $code = self::SUCCESS;
        foreach ($groups as $provider => $alvoIds) {
            foreach ($alvoIds as $nome => $id) {
                $gabarito = collect($alvos)->firstWhere('nome', $nome)['gabarito'] ?? null;
                $groupCode = Artisan::call('egide:bench', array_filter([...$options, '--sessao' => [$id], '--gabarito' => $gabarito]));
                $code = $groupCode !== self::SUCCESS ? $groupCode : $code;
                $matrix["{$provider}:{$nome}"] = json_decode(trim(Artisan::output()), true);
            }
        }
        $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION;
        $report = json_encode(['alvos' => $matrix], $flags);
        if ($path = $this->option('saida')) {
            file_put_contents($path, $report.PHP_EOL);
            $this->info("Relatório gravado em {$path}.");
        } else {
            $this->line($report);
        }

        $unfinished = Scan::whereKey($ids)->where('status', '!=', 'completed')->count();

        return $code !== self::SUCCESS || $unfinished === count($ids) ? self::FAILURE : self::SUCCESS;
    }

    private function alvos(): ?array
    {
        $path = (string) ($this->option('alvos') ?: 'bench/alvos.json');
        $data = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;
        if (! is_array($data) || ($data['alvos'] ?? null) === null) {
            $this->error("Arquivo de alvos inválido ou ausente: {$path}. Veja bench/alvos.json de exemplo.");

            return null;
        }
        $alvos = [];
        foreach ($data['alvos'] as $alvo) {
            if (! is_array($alvo) || ! is_string($alvo['nome'] ?? null) || ! is_string($alvo['origem'] ?? null)
                || ! is_int($alvo['porta'] ?? null)) {
                $this->error('Cada alvo precisa de nome, origem e porta (inteira).');

                return null;
            }
            $alvos[] = $alvo;
        }

        return $alvos;
    }

    private function launch(User $user, array $alvo, int $budget, ?array $engine): string
    {
        $credentials = null;
        foreach (['a', 'b'] as $actor) {
            $account = $alvo['credenciais'][$actor] ?? null;
            if (is_array($account) && ! empty($account['email'])) {
                $credentials[$actor] = [
                    'email' => $account['email'], 'password' => $account['senha'] ?? null,
                    'marker' => $account['marcador'] ?? null, 'origin' => null,
                    'path' => $account['rota'] ?? null, 'role' => ($account['papel'] ?? 'normal') === 'admin' ? 'admin' : 'normal',
                ];
            }
        }

        $target = Target::updateOrCreate(
            ['user_id' => $user->id, 'origin' => $alvo['origem']],
            [
                'name' => $alvo['nome'],
                'entry_path' => $alvo['entrada'] ?? '/',
                'rules' => $alvo['regras'] ?? [['method' => '*', 'path' => '/', 'prefix' => true]],
                'denied' => $alvo['negadas'] ?? [],
                'credentials' => $credentials,
                'local_port' => $alvo['porta'],
                'write_test' => (bool) ($alvo['teste_escrita'] ?? false),
                'environment_type' => 'test',
                'safety' => 'livre',
                'verified_at' => now(),
                'focus' => $alvo['foco'] ?? null,
            ],
        );

        return DB::transaction(function () use ($user, $target, $alvo, $budget, $engine) {
            $scan = Scan::create([
                'user_id' => $user->id, 'target_id' => $target->id,
                'name' => 'Benchmark · '.$alvo['nome'],
                'mode' => 'external',
                'scope' => [...Scope::launch($target), 'nav_model' => $engine['nav_model'] ?? null],
                'provider' => $engine['provider'] ?? 'lab',
                'model' => $engine['model'] ?? null,
                'engine_key' => $engine['key'] ?? null,
                'credentials' => $target->credentials,
                'budget' => Scope::budget('external', 'test', $budget),
            ]);
            $scan->event('system', 'Sessão recebida', 'Benchmark de alvo: aguardando o executor na fila Horizon.');
            RunScan::dispatch($scan->id)->afterCommit();

            return $scan->id;
        });
    }
}
