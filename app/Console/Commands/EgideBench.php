<?php

namespace App\Console\Commands;

use App\Models\Scan;
use App\Models\ScanEvent;
use Illuminate\Console\Command;
use Symfony\Component\Console\Output\OutputInterface;

class EgideBench extends Command
{
    public const CONFIGURATION_CATEGORIES = [
        'Configuração · cabeçalhos HTTP',
        'Configuração · cookies',
        'InventoryCheck · inventário de API',
    ];

    public const BUDGET_EVENT = 'Orçamento por fase';

    private const EMPTY = 'Nenhuma sessão de laboratório concluída encontrada.';

    private const VERDICTS = ['nao_testado' => 0, 'protegido' => 1, 'falha' => 2];

    protected $signature = 'egide:bench
        {--modo=laboratory : Modo das sessões medidas: laboratory ou external}
        {--last=10 : Quantidade de sessões concluídas mais recentes de cada variante}
        {--json : Imprime o relatório em JSON}
        {--sessao=* : Limita o relatório a estas sessões}
        {--gabarito= : JSON com a lista de falhas plantadas esperadas (ex.: tests/fixtures/lab-gabarito.json)}
        {--min= : Fração mínima do gabarito que precisa ser detectada (ex.: 0.9); falha o comando se ficar abaixo}';

    protected $description = 'Mede detecção, falso positivo e custo do agente nas sessões de laboratório concluídas';

    public function handle(): int
    {
        $last = filter_var($this->option('last'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 1000]]);
        if ($last === false) {
            $this->error('Informe --last com um número inteiro entre 1 e 1000.');

            return self::FAILURE;
        }

        $modo = (string) $this->option('modo');
        if (! in_array($modo, ['laboratory', 'external'], true)) {
            $this->error('Informe --modo como laboratory ou external.');

            return self::FAILURE;
        }
        $external = $modo === 'external';
        $originals = $external ? $this->rows('external', 'externo', $last, false) : $this->rows('laboratory', 'vulneravel', $last);
        $retests = $external ? $this->rows('external', 'reteste', $last, true) : $this->rows('retest', 'corrigido', $last);
        $report = [
            'parametros' => ['last' => $last, 'categorias_configuracao' => self::CONFIGURATION_CATEGORIES],
            'originais' => $this->detection($originals),
            'retestes' => $this->falsePositives($retests),
            'custo' => ['originais' => $this->cost($originals), 'retestes' => $this->cost($retests)],
            'sessoes' => [...$originals, ...$retests],
        ];

        $gabarito = $this->gabarito($report['originais']);
        if ($gabarito !== null) {
            $report['gabarito'] = $gabarito;
        }
        $min = filter_var($this->option('min'), FILTER_VALIDATE_FLOAT, ['options' => ['min_range' => 0, 'max_range' => 1]]);
        if ($this->option('min') !== null && $min === false) {
            $this->error('Informe --min como fração entre 0 e 1 (ex.: 0.9).');

            return self::FAILURE;
        }
        if ($report['sessoes'] === []) {
            $report['mensagem'] = self::EMPTY;
        }
        $belowMin = $gabarito !== null && $min !== null && ($gabarito['cobertura'] ?? 0) < $min;
        if ($belowMin) {
            $report['gabarito']['minimo'] = $min;
            $report['gabarito']['reprovado'] = true;
        }

        if ($this->option('json')) {
            $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION;
            $this->output->writeln(json_encode($report, $flags), OutputInterface::OUTPUT_RAW);
        } elseif ($report['sessoes'] === []) {
            $this->warn(self::EMPTY);
        } else {
            $this->render($report);
        }

        if ($belowMin) {
            if (! $this->option('json')) {
                $this->error("Cobertura do gabarito abaixo do mínimo: {$this->percent($gabarito['cobertura'])} < {$this->percent($min)}.");
            }

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    private function gabarito(array $originals): ?array
    {
        $path = $this->option('gabarito');
        if (! is_string($path) || $path === '') {
            return null;
        }
        if (! is_file($path)) {
            $path = base_path($path);
        }
        $data = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;
        $expected = collect($data['classes'] ?? [])->filter(fn ($class) => is_string($class) && $class !== '')->unique()->sort()->values();
        if ($expected->isEmpty()) {
            return null;
        }
        $detected = collect($originals['classes'] ?? [])->where('pass_at_k', true)->pluck('classe');
        $tested = collect($originals['classes'] ?? [])->filter(fn ($class) => $class['sessoes_testadas'] > 0)->pluck('classe');
        $missing = $expected->diff($detected)->values();
        $neverTested = $expected->diff($tested)->values();
        $covered = $expected->count() - $missing->count();

        return [
            'arquivo' => $path,
            'esperadas' => $expected->count(),
            'detectadas' => $covered,
            'cobertura' => $this->ratio($covered, $expected->count()),
            'faltantes' => $missing->all(),
            'nunca_testadas' => $neverTested->all(),
        ];
    }

    private function rows(string $mode, string $variant, int $last, ?bool $retestOf = null): array
    {
        $scans = Scan::query()->where('status', 'completed')->where('mode', $mode)
            ->when($mode !== 'external', fn ($query) => $query->where('scope->lab', true))
            ->when($retestOf !== null, fn ($query) => $retestOf ? $query->whereNotNull('scope->retest_of') : $query->whereNull('scope->retest_of'))
            ->when($this->option('sessao'), fn ($query, $ids) => $query->whereKey($ids))
            ->with(['findings' => fn ($query) => $query->achados()])
            ->latest()->orderByDesc('id')->limit($last)->get();
        $budgets = ScanEvent::whereIn('scan_id', $scans->modelKeys())->where('title', self::BUDGET_EVENT)
            ->orderBy('id')->get()->keyBy('scan_id');

        return $scans->map(fn (Scan $scan) => $this->row($scan, $variant, (array) $budgets->get($scan->id)?->data))->all();
    }

    private function row(Scan $scan, string $variant, array $budget): array
    {
        $classes = [];
        foreach ((array) $scan->coverage as $item) {
            $check = is_array($item) ? ($item['check'] ?? null) : null;
            if (! is_string($check) || $check === '') {
                continue;
            }
            $verdict = is_string($item['verdict'] ?? null) ? $item['verdict'] : 'nao_testado';
            $current = $classes[$check] ?? 'nao_testado';
            $classes[$check] = (self::VERDICTS[$verdict] ?? 0) > self::VERDICTS[$current] ? $verdict : $current;
        }
        if (! in_array($variant, ['corrigido', 'reteste'], true)) {
            foreach ($scan->findings->pluck('category')->filter(fn ($category) => is_string($category) && $category !== '') as $category) {
                $classes[$category] = 'falha';
            }
        }
        ksort($classes);

        $falsePositives = in_array($variant, ['corrigido', 'reteste'], true)
            ? $scan->findings->reject(fn ($finding) => in_array($finding->category, self::CONFIGURATION_CATEGORIES, true))->pluck('category')->values()->all()
            : null;
        $started = $scan->started_at;
        $finished = $scan->finished_at;

        return [
            'id' => $scan->id,
            'variante' => $variant,
            'provedor' => $scan->provider,
            'concluida_em' => $finished?->toIso8601String(),
            'classes' => $classes,
            'achados' => $scan->findings->count(),
            'falsos_positivos' => $falsePositives === null ? null : count($falsePositives),
            'categorias_fp' => $falsePositives,
            'requisicoes' => $this->requests($scan),
            'duracao_s' => $started && $finished ? max(0, $finished->getTimestamp() - $started->getTimestamp()) : null,
            'tokens' => $this->tokens($budget),
        ];
    }

    private function detection(array $rows): array
    {
        $k = count($rows);
        $classes = collect($rows)->flatMap(fn ($row) => array_map('strval', array_keys($row['classes'])))->unique()
            ->map(function (string $class) use ($rows, $k) {
                $failed = count(array_filter($rows, fn ($row) => ($row['classes'][$class] ?? null) === 'falha'));
                $tested = count(array_filter($rows, fn ($row) => in_array($row['classes'][$class] ?? null, ['falha', 'protegido'], true)));

                return [
                    'classe' => $class, 'sessoes_com_falha' => $failed, 'sessoes_testadas' => $tested,
                    'taxa_deteccao' => $this->ratio($failed, $k), 'pass_at_k' => $failed > 0,
                ];
            })
            ->sort(fn ($a, $b) => [$b['sessoes_com_falha'], $b['sessoes_testadas'], $a['classe']] <=> [$a['sessoes_com_falha'], $a['sessoes_testadas'], $b['classe']])
            ->values();
        $union = $classes->where('pass_at_k', true)->pluck('classe')->values()->all();

        return [
            'sessoes' => $k,
            'k' => $k,
            'classes' => $classes->all(),
            'pass_at_1' => $this->ratio($classes->sum('sessoes_com_falha'), $k * $classes->count()),
            'uniao' => $union,
            'cobertura_uniao' => $this->ratio(count($union), $classes->count()),
            'achados_por_sessao' => $this->ratio(array_sum(array_column($rows, 'achados')), $k),
        ];
    }

    private function falsePositives(array $rows): array
    {
        $count = count($rows);
        $categories = collect($rows)->flatMap(fn ($row) => $row['categorias_fp'])->countBy()->sortKeys()->sortDesc();
        $total = (int) $categories->sum();
        $affected = count(array_filter($rows, fn ($row) => $row['falsos_positivos'] > 0));

        return [
            'sessoes' => $count,
            'falsos_positivos' => $total,
            'fp_por_sessao' => $this->ratio($total, $count),
            'sessoes_com_fp' => $affected,
            'taxa_sessoes_com_fp' => $this->ratio($affected, $count),
            'categorias_fp' => $categories->all(),
        ];
    }

    private function cost(array $rows): array
    {
        $rows = collect($rows);
        $durations = $rows->pluck('duracao_s')->reject(fn ($value) => $value === null);
        $tokens = $rows->pluck('tokens')->reject(fn ($value) => $value === null);

        return [
            'requisicoes_media' => $rows->isEmpty() ? null : round($rows->avg('requisicoes'), 2),
            'duracao_media_s' => $durations->isEmpty() ? null : round($durations->avg(), 2),
            'requisicoes_por_achado' => $this->ratio($rows->sum('requisicoes'), $rows->sum('achados')),
            'tokens_media' => $tokens->isEmpty() ? null : round($tokens->avg(), 2),
            'sessoes_com_tokens' => $tokens->count(),
        ];
    }

    private function requests(Scan $scan): int
    {
        $reported = $scan->summary['requests'] ?? null;

        return is_numeric($reported) ? (int) $reported : (int) $scan->request_count;
    }

    private function tokens(array $data): ?int
    {
        $tokens = $data['tokens'] ?? null;
        if (is_array($tokens)) {
            $parts = array_filter($tokens, 'is_numeric');
            $tokens = is_numeric($tokens['total'] ?? null) ? $tokens['total'] : ($parts ? array_sum($parts) : null);
        }

        return is_numeric($tokens) ? (int) $tokens : null;
    }

    private function ratio(int|float $part, int|float $whole): ?float
    {
        return $whole > 0 ? round($part / $whole, 4) : null;
    }

    private function render(array $report): void
    {
        $originals = $report['originais'];
        $retests = $report['retestes'];
        $this->info("Égide-MT · benchmark do laboratório (até {$report['parametros']['last']} sessões concluídas por variante)");

        $this->newLine();
        $this->line("<options=bold>Originais (variante vulnerável)</>: {$this->sessions($originals['sessoes'])}");
        if ($originals['classes'] !== []) {
            $this->table(
                ['Classe de verificação', 'Sessões com falha', 'Sessões testadas', 'Taxa de detecção', "pass@{$originals['k']}"],
                array_map(fn ($class) => [
                    $class['classe'], $class['sessoes_com_falha'], $class['sessoes_testadas'],
                    $this->percent($class['taxa_deteccao']), $class['pass_at_k'] ? 'sim' : 'não',
                ], $originals['classes']),
            );
            $this->line('pass@1 médio: '.$this->percent($originals['pass_at_1'])
                .' · Cobertura por união (pass@'.$originals['k'].'): '.$this->percent($originals['cobertura_uniao'])
                .' ('.count($originals['uniao']).' de '.count($originals['classes']).' classes)');
        } elseif ($originals['sessoes'] > 0) {
            $this->line('Nenhuma classe de verificação registrada na cobertura dessas sessões.');
        }
        $this->line('Achados por sessão: '.$this->number($originals['achados_por_sessao']));

        $gabarito = $report['gabarito'] ?? null;
        if ($gabarito !== null) {
            $this->newLine();
            $this->line('<options=bold>Gabarito</>: '.$this->percent($gabarito['cobertura'])
                ." ({$gabarito['detectadas']} de {$gabarito['esperadas']} falhas plantadas detectadas)");
            if ($gabarito['faltantes'] !== []) {
                $this->line('Faltantes: '.implode(' · ', $gabarito['faltantes']));
            }
            if ($gabarito['nunca_testadas'] !== []) {
                $this->line('Nunca testadas: '.implode(' · ', $gabarito['nunca_testadas']));
            }
        }

        $this->newLine();
        $this->line("<options=bold>Retestes (variante corrigida)</>: {$this->sessions($retests['sessoes'])}");
        if ($retests['sessoes'] > 0) {
            $this->line("Falsos positivos: {$retests['falsos_positivos']} ({$this->number($retests['fp_por_sessao'])} por sessão)"
                ." · Sessões com falso positivo: {$retests['sessoes_com_fp']} de {$retests['sessoes']} ({$this->percent($retests['taxa_sessoes_com_fp'])})");
            if ($retests['categorias_fp'] !== []) {
                $this->table(['Categoria do falso positivo', 'Ocorrências'], collect($retests['categorias_fp'])->map(fn ($total, $category) => [$category, $total])->values()->all());
            }
        }

        $this->newLine();
        $this->line('<options=bold>Custo</>');
        $this->table(
            ['Grupo', 'Requisições por sessão', 'Duração média', 'Requisições por achado', 'Tokens por sessão'],
            collect(['Originais' => $report['custo']['originais'], 'Retestes' => $report['custo']['retestes']])->map(fn ($cost, $group) => [
                $group, $this->number($cost['requisicoes_media']), $this->seconds($cost['duracao_media_s']),
                $this->number($cost['requisicoes_por_achado']), $cost['tokens_media'] === null ? 'sem dados' : $this->number($cost['tokens_media'], 0),
            ])->values()->all(),
        );

        $this->newLine();
        $this->line('<options=bold>Sessões</>');
        $this->table(
            ['Sessão', 'Variante', 'Provedor', 'Classes com falha', 'Achados', 'Falsos positivos', 'Requisições', 'Duração', 'Tokens'],
            array_map(fn ($row) => [
                $row['id'], $row['variante'], $row['provedor'], count(array_keys($row['classes'], 'falha', true)),
                $row['achados'], $row['falsos_positivos'] ?? '—', $row['requisicoes'], $this->seconds($row['duracao_s']), $this->number($row['tokens'], 0),
            ], $report['sessoes']),
        );
    }

    private function sessions(int $count): string
    {
        return $count === 0 ? 'nenhuma sessão concluída' : $count.' '.($count === 1 ? 'sessão' : 'sessões');
    }

    private function percent(?float $value): string
    {
        return $value === null ? '—' : number_format($value * 100, 1, ',', '.').'%';
    }

    private function number(int|float|null $value, int $decimals = 1): string
    {
        return $value === null ? '—' : number_format($value, $decimals, ',', '.');
    }

    private function seconds(int|float|null $value): string
    {
        return $value === null ? '—' : number_format($value, 0, ',', '.').' s';
    }
}
