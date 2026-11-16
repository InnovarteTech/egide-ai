<?php

namespace App\Security;

use Closure;
use InvalidArgumentException;
use LogicException;

class BudgetLedger
{
    public const PHASES = [
        'observacao' => 0.10,
        'semeadura' => 0.05,
        'prova_cruzada' => 0.15,
        'probers' => 0.20,
        'caca' => 0.35,
        'reproducao' => 0.15,
    ];

    public const LABELS = [
        'observacao' => 'observação',
        'semeadura' => 'semeadura',
        'prova_cruzada' => 'prova entre contas',
        'probers' => 'sondas determinísticas',
        'caca' => 'caça',
        'reproducao' => 'reprodução',
    ];

    public const POOL = 'caca';

    public const LOCKED = 'reproducao';

    public const STRICT = 'estrito';

    public const GUARANTEED = 'minimos';

    private int $reserve;

    private int $base;

    private array $allocated = [];

    private array $spent = [];

    private array $closed = [];

    private array $started = [];

    private array $elapsed = [];

    private ?string $current = null;

    private ?float $since = null;

    private Closure $clock;

    public function __construct(
        private int $total,
        int $configurationReserve = 22,
        array $fractions = self::PHASES,
        private string $mode = self::STRICT,
        ?Closure $clock = null,
    ) {
        if ($total < 0 || $configurationReserve < 0) {
            throw new InvalidArgumentException('Orçamento e reserva não podem ser negativos.');
        }
        if (! in_array($mode, [self::STRICT, self::GUARANTEED], true)) {
            throw new InvalidArgumentException("Modo de orçamento desconhecido: {$mode}.");
        }
        foreach ($fractions as $phase => $fraction) {
            $this->phase((string) $phase);
            if ((! is_int($fraction) && ! is_float($fraction)) || $fraction < 0) {
                throw new InvalidArgumentException("Fração de orçamento inválida para a fase {$phase}.");
            }
        }
        if (array_sum($fractions) > 1 + 1e-9) {
            throw new InvalidArgumentException('As frações do orçamento somam mais de 100%.');
        }

        $this->clock = $clock ?? fn (): float => microtime(true);
        $this->reserve = min($total, $configurationReserve);
        $this->base = $total - $this->reserve;

        foreach (array_keys(self::PHASES) as $phase) {
            $this->allocated[$phase] = (int) floor(round($this->base * ($fractions[$phase] ?? 0), 6));
            $this->spent[$phase] = 0;
            $this->closed[$phase] = false;
            $this->started[$phase] = false;
            $this->elapsed[$phase] = 0.0;
        }

        $this->allocated[self::POOL] += $this->base - array_sum($this->allocated);
    }

    public function begin(string $phase): void
    {
        $phase = $this->phase($phase);
        $this->tick();
        $this->current = $phase;
        $this->started[$phase] = true;
    }

    public function pause(): void
    {
        $this->tick();
        $this->current = null;
    }

    public function current(): ?string
    {
        return $this->current;
    }

    public function allows(int $cost, ?string $phase = null): bool
    {
        $phase = $this->resolve($phase);
        $this->guardAmount($cost);

        return ! $this->closed[$phase] && $cost <= $this->remaining($phase);
    }

    public function spend(int $n, ?string $phase = null): bool
    {
        $phase = $this->resolve($phase);
        $this->guardAmount($n);
        $within = $this->allows($n, $phase);
        $this->spent[$phase] += $n;

        return $within;
    }

    public function close(string $phase): void
    {
        $phase = $this->phase($phase);

        if ($this->closed[$phase]) {
            return;
        }

        $this->closed[$phase] = true;

        if ($this->mode === self::GUARANTEED || $phase === self::POOL || $phase === self::LOCKED) {
            return;
        }

        $leftover = $this->remaining($phase);
        $this->allocated[$phase] -= $leftover;
        $this->allocated[self::POOL] += $leftover;
    }

    public function remaining(?string $phase = null): int
    {
        $phase = $this->resolve($phase);
        $own = max(0, $this->allocated[$phase] - $this->spent[$phase]);

        if ($this->mode === self::STRICT) {
            return $own;
        }
        if ($this->closed[$phase]) {
            return 0;
        }

        $free = max(0, $this->base - array_sum($this->spent));
        $held = 0;
        foreach (array_keys(self::PHASES) as $other) {
            if ($other !== $phase && ! $this->started[$other]) {
                $held += $this->unused($other);
            }
        }

        return min($free, max($own, $free - $held));
    }

    public function durations(): array
    {
        $this->tick();

        return array_map(fn (float $seconds): float => round($seconds, 1), $this->elapsed);
    }

    public function summary(): array
    {
        $summary = [];

        foreach (array_keys(self::PHASES) as $phase) {
            $summary[$phase] = [
                'allocated' => $this->allocated[$phase],
                'spent' => $this->spent[$phase],
                'left' => $this->unused($phase),
                'closed' => $this->closed[$phase],
            ];
        }

        $summary['total'] = [
            'budget' => $this->total,
            'reserve' => $this->reserve,
            'allocated' => $this->base,
            'spent' => array_sum($this->spent),
            'left' => $this->mode === self::STRICT
                ? array_sum(array_column($summary, 'left'))
                : max(0, $this->base - array_sum($this->spent)),
        ];

        return $summary;
    }

    private function unused(string $phase): int
    {
        if ($this->mode === self::STRICT) {
            return $this->remaining($phase);
        }

        return $this->closed[$phase] ? 0 : max(0, $this->allocated[$phase] - $this->spent[$phase]);
    }

    private function tick(): void
    {
        $now = (float) ($this->clock)();
        if ($this->current !== null && $this->since !== null) {
            $this->elapsed[$this->current] += max(0.0, $now - $this->since);
        }
        $this->since = $now;
    }

    private function resolve(?string $phase): string
    {
        if ($phase !== null) {
            return $this->phase($phase);
        }

        if ($this->current === null) {
            throw new LogicException('Nenhuma fase do orçamento foi iniciada.');
        }

        return $this->current;
    }

    private function phase(string $phase): string
    {
        if (! array_key_exists($phase, self::PHASES)) {
            throw new InvalidArgumentException("Fase de orçamento desconhecida: {$phase}.");
        }

        return $phase;
    }

    private function guardAmount(int $amount): void
    {
        if ($amount < 0) {
            throw new InvalidArgumentException('Custo de orçamento não pode ser negativo.');
        }
    }
}
