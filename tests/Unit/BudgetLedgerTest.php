<?php

namespace Tests\Unit;

use App\Security\BudgetLedger;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class BudgetLedgerTest extends TestCase
{
    private function allocations(BudgetLedger $ledger): array
    {
        return array_map(fn (array $row) => $row['allocated'], array_intersect_key($ledger->summary(), BudgetLedger::PHASES));
    }

    public function test_allocates_contract_fractions_after_the_configuration_reserve(): void
    {
        $ledger = new BudgetLedger(122);

        $this->assertSame([
            'observacao' => 10,
            'semeadura' => 5,
            'prova_cruzada' => 15,
            'probers' => 20,
            'caca' => 35,
            'reproducao' => 15,
        ], $this->allocations($ledger));

        $this->assertSame(['budget' => 122, 'reserve' => 22, 'allocated' => 100, 'spent' => 0, 'left' => 100], $ledger->summary()['total']);
    }

    public function test_rounding_remainder_goes_to_caca_so_nothing_is_lost(): void
    {
        $ledger = new BudgetLedger(80);

        $this->assertSame([
            'observacao' => 5,
            'semeadura' => 2,
            'prova_cruzada' => 8,
            'probers' => 11,
            'caca' => 24,
            'reproducao' => 8,
        ], $this->allocations($ledger));
        $this->assertSame(58, array_sum($this->allocations($ledger)));
    }

    public function test_custom_reserve_and_budget_smaller_than_the_reserve(): void
    {
        $noReserve = new BudgetLedger(100, 0);
        $this->assertSame(10, $noReserve->remaining('observacao'));
        $this->assertSame(0, $noReserve->summary()['total']['reserve']);

        $tiny = new BudgetLedger(10);
        $this->assertSame(['budget' => 10, 'reserve' => 10, 'allocated' => 0, 'spent' => 0, 'left' => 0], $tiny->summary()['total']);
        $tiny->begin('caca');
        $this->assertFalse($tiny->allows(1));
    }

    public function test_allows_and_spend_use_the_current_phase_and_respect_its_limit(): void
    {
        $ledger = new BudgetLedger(122);
        $ledger->begin('observacao');

        $this->assertSame('observacao', $ledger->current());
        $this->assertTrue($ledger->allows(10));
        $this->assertFalse($ledger->allows(11));

        $this->assertTrue($ledger->spend(4));
        $this->assertSame(6, $ledger->remaining());
        $this->assertFalse($ledger->allows(7));
        $this->assertTrue($ledger->allows(6));

        $this->assertTrue($ledger->allows(20, 'probers'));
        $this->assertFalse($ledger->allows(21, 'probers'));
        $this->assertTrue($ledger->spend(3, 'probers'));
        $this->assertSame(17, $ledger->remaining('probers'));
        $this->assertSame(6, $ledger->remaining('observacao'));
    }

    public function test_overspend_is_recorded_but_left_never_goes_negative(): void
    {
        $ledger = new BudgetLedger(122);
        $ledger->begin('semeadura');

        $this->assertFalse($ledger->spend(7));
        $this->assertSame(0, $ledger->remaining());
        $this->assertFalse($ledger->allows(1));
        $this->assertTrue($ledger->allows(0));
        $this->assertSame(['allocated' => 5, 'spent' => 7, 'left' => 0, 'closed' => false], $ledger->summary()['semeadura']);
        $this->assertSame(35, $ledger->remaining('caca'));
    }

    public function test_closing_a_phase_rolls_its_leftover_into_caca(): void
    {
        $ledger = new BudgetLedger(122);
        $ledger->begin('observacao');
        $ledger->spend(4);
        $ledger->close('observacao');

        $this->assertSame(0, $ledger->remaining('observacao'));
        $this->assertFalse($ledger->allows(1, 'observacao'));
        $this->assertSame(41, $ledger->remaining('caca'));

        $ledger->close('semeadura');
        $ledger->close('semeadura');
        $this->assertSame(46, $ledger->remaining('caca'));

        $ledger->begin('prova_cruzada');
        $ledger->spend(15);
        $ledger->close('prova_cruzada');
        $this->assertSame(46, $ledger->remaining('caca'));

        $ledger->begin('caca');
        $this->assertTrue($ledger->allows(46));
        $this->assertFalse($ledger->allows(47));
        $this->assertSame(['allocated' => 4, 'spent' => 4, 'left' => 0, 'closed' => true], $ledger->summary()['observacao']);
    }

    public function test_caca_never_feeds_other_phases(): void
    {
        $ledger = new BudgetLedger(122);
        $ledger->begin('caca');
        $ledger->spend(5);
        $ledger->close('caca');

        $this->assertSame(20, $ledger->remaining('probers'));
        $this->assertSame(15, $ledger->remaining('reproducao'));
        $this->assertSame(10, $ledger->remaining('observacao'));
        $this->assertFalse($ledger->allows(1, 'caca'));

        $ledger->begin('probers');
        $this->assertFalse($ledger->allows(21));
    }

    public function test_reproducao_is_untouchable_by_other_phases(): void
    {
        $ledger = new BudgetLedger(122);

        foreach (['observacao', 'semeadura', 'prova_cruzada', 'probers'] as $phase) {
            $ledger->close($phase);
        }

        $ledger->begin('caca');
        $this->assertSame(85, $ledger->remaining());
        $ledger->spend(85);
        $this->assertFalse($ledger->allows(1));
        $this->assertSame(15, $ledger->remaining('reproducao'));

        $this->assertTrue($ledger->allows(15, 'reproducao'));
        $this->assertTrue($ledger->spend(2, 'reproducao'));
        $this->assertSame(13, $ledger->remaining('reproducao'));

        $ledger->close('reproducao');
        $this->assertSame(0, $ledger->remaining('caca'));
        $this->assertSame(13, $ledger->remaining('reproducao'));
        $this->assertFalse($ledger->allows(1, 'reproducao'));
        $this->assertSame(['allocated' => 15, 'spent' => 2, 'left' => 13, 'closed' => true], $ledger->summary()['reproducao']);
    }

    public function test_summary_reports_every_phase_and_totals(): void
    {
        $ledger = new BudgetLedger(122);
        $ledger->begin('observacao');
        $ledger->spend(3);
        $ledger->close('observacao');
        $ledger->begin('caca');
        $ledger->spend(10);

        $summary = $ledger->summary();

        $this->assertSame([...array_keys(BudgetLedger::PHASES), 'total'], array_keys($summary));
        $this->assertSame(['allocated' => 42, 'spent' => 10, 'left' => 32, 'closed' => false], $summary['caca']);
        $this->assertSame(['budget' => 122, 'reserve' => 22, 'allocated' => 100, 'spent' => 13, 'left' => 87], $summary['total']);
    }

    public static function unknownPhaseCalls(): array
    {
        return [
            'begin' => [fn (BudgetLedger $l) => $l->begin('ataque')],
            'allows' => [fn (BudgetLedger $l) => $l->allows(1, 'ataque')],
            'spend' => [fn (BudgetLedger $l) => $l->spend(1, 'ataque')],
            'close' => [fn (BudgetLedger $l) => $l->close('ataque')],
            'remaining' => [fn (BudgetLedger $l) => $l->remaining('ataque')],
        ];
    }

    #[DataProvider('unknownPhaseCalls')]
    public function test_unknown_phase_throws(callable $call): void
    {
        $this->expectException(InvalidArgumentException::class);

        $call(new BudgetLedger(122));
    }

    public function test_using_the_current_phase_before_begin_throws(): void
    {
        $this->expectException(LogicException::class);

        (new BudgetLedger(122))->allows(1);
    }

    private const SHARES = ['observacao' => 0.15, 'semeadura' => 0, 'prova_cruzada' => 0.15, 'probers' => 0.30, 'caca' => 0.40, 'reproducao' => 0];

    private function guaranteed(int $total = 122, ?\Closure $clock = null): BudgetLedger
    {
        return new BudgetLedger($total, fractions: self::SHARES, mode: BudgetLedger::GUARANTEED, clock: $clock);
    }

    public function test_custom_fractions_set_the_minimum_of_each_phase(): void
    {
        $expected = ['observacao' => 15, 'semeadura' => 0, 'prova_cruzada' => 15, 'probers' => 30, 'caca' => 40, 'reproducao' => 0];

        $this->assertSame($expected, $this->allocations($this->guaranteed()));
        $this->assertSame(['budget' => 122, 'reserve' => 22, 'allocated' => 100, 'spent' => 0, 'left' => 100], $this->guaranteed()->summary()['total']);

        $strict = new BudgetLedger(122, fractions: self::SHARES);
        $this->assertSame($expected, $this->allocations($strict));
        $strict->begin('probers');
        $this->assertTrue($strict->allows(30));
        $this->assertFalse($strict->allows(31));
    }

    public function test_a_phase_may_exceed_its_share_while_phases_not_started_keep_their_minimum(): void
    {
        $ledger = $this->guaranteed();
        $ledger->begin('observacao');
        $this->assertSame(15, $ledger->remaining());
        $ledger->spend(10);

        $ledger->begin('probers');
        $this->assertSame(35, $ledger->remaining());
        $this->assertTrue($ledger->allows(35));
        $this->assertFalse($ledger->allows(36));
        $this->assertTrue($ledger->spend(35));
        $this->assertFalse($ledger->allows(1));

        $ledger->begin('caca');
        $this->assertSame(40, $ledger->remaining());
        $ledger->spend(40);
        $this->assertFalse($ledger->allows(1));

        $ledger->begin('probers');
        $this->assertSame(0, $ledger->remaining());

        $ledger->begin('prova_cruzada');
        $this->assertSame(15, $ledger->remaining());
        $ledger->spend(15);
        $this->assertFalse($ledger->allows(1));
        $this->assertSame(['budget' => 122, 'reserve' => 22, 'allocated' => 100, 'spent' => 100, 'left' => 0], $ledger->summary()['total']);
    }

    public function test_closing_a_phase_that_will_not_run_releases_its_minimum(): void
    {
        $ledger = $this->guaranteed();
        $ledger->begin('probers');
        $this->assertSame(30, $ledger->remaining());

        $ledger->close('prova_cruzada');

        $this->assertSame(45, $ledger->remaining());
        $this->assertFalse($ledger->allows(1, 'prova_cruzada'));
        $this->assertSame(['allocated' => 15, 'spent' => 0, 'left' => 0, 'closed' => true], $ledger->summary()['prova_cruzada']);
    }

    public function test_oversubscribed_minimums_never_spend_past_the_configuration_reserve(): void
    {
        $ledger = $this->guaranteed();
        $ledger->begin('observacao');
        $this->assertFalse($ledger->spend(60));
        $this->assertSame(0, $ledger->remaining());

        $ledger->begin('probers');
        $this->assertSame(30, $ledger->remaining());
        $ledger->spend(30);

        $ledger->begin('caca');
        $this->assertSame(10, $ledger->remaining());
        $ledger->spend(10);

        $ledger->begin('prova_cruzada');
        $this->assertSame(0, $ledger->remaining());
        $this->assertSame(['budget' => 122, 'reserve' => 22, 'allocated' => 100, 'spent' => 100, 'left' => 0], $ledger->summary()['total']);
        $this->assertSame(['allocated' => 15, 'spent' => 60, 'left' => 0, 'closed' => false], $ledger->summary()['observacao']);
    }

    public function test_durations_accumulate_per_phase_and_pause_stops_the_clock(): void
    {
        $now = 100.0;
        $ledger = $this->guaranteed(clock: function () use (&$now) {
            return $now;
        });

        $ledger->begin('observacao');
        $now = 112.0;
        $ledger->begin('probers');
        $now = 120.0;
        $ledger->pause();
        $this->assertNull($ledger->current());
        $now = 150.0;
        $ledger->begin('probers');
        $now = 155.5;

        $this->assertSame(['observacao' => 12.0, 'semeadura' => 0.0, 'prova_cruzada' => 0.0, 'probers' => 13.5, 'caca' => 0.0, 'reproducao' => 0.0], $ledger->durations());
    }

    public static function invalidConfigurations(): array
    {
        return [
            'fase desconhecida' => [fn () => new BudgetLedger(100, fractions: ['ataque' => 0.5])],
            'fração negativa' => [fn () => new BudgetLedger(100, fractions: ['caca' => -0.1])],
            'fração não numérica' => [fn () => new BudgetLedger(100, fractions: ['caca' => '0.4'])],
            'soma acima de 100%' => [fn () => new BudgetLedger(100, fractions: ['caca' => 0.8, 'probers' => 0.3])],
            'modo desconhecido' => [fn () => new BudgetLedger(100, mode: 'livre')],
        ];
    }

    #[DataProvider('invalidConfigurations')]
    public function test_invalid_configuration_is_rejected(callable $build): void
    {
        $this->expectException(InvalidArgumentException::class);

        $build();
    }

    public function test_negative_amounts_are_rejected(): void
    {
        $ledger = new BudgetLedger(122);
        $ledger->begin('caca');

        foreach ([fn () => $ledger->allows(-1), fn () => $ledger->spend(-1), fn () => new BudgetLedger(-1), fn () => new BudgetLedger(100, -1)] as $call) {
            try {
                $call();
                $this->fail('Valor negativo deveria ser rejeitado.');
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }

        $this->assertSame(35, $ledger->remaining());
    }
}
