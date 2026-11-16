<?php

namespace Tests\Feature;

use App\Models\Hypothesis;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use InvalidArgumentException;
use Tests\TestCase;

class HypothesisModelTest extends TestCase
{
    use RefreshDatabase;

    private function scan(): Scan
    {
        return Scan::create(['user_id' => User::factory()->create()->id, 'name' => 'Lab', 'mode' => 'laboratory', 'scope' => ['lab' => true], 'status' => 'running']);
    }

    private function hypothesis(Scan $scan, array $attributes = []): Hypothesis
    {
        return Hypothesis::create(array_merge([
            'scan_id' => $scan->id,
            'class' => 'bola',
            'method' => 'GET',
            'path' => '/api/faturas/{id}',
            'point' => 'path',
            'key' => 'id',
            'actor' => 'b',
            'oracle' => 'canario_cruzado',
            'action_class' => 'leitura',
            'expected' => 'Conta B não deve ler a fatura da conta A.',
            'rationale' => 'Identificador sequencial na rota.',
        ], $attributes));
    }

    public function test_migration_creates_hypotheses_table_with_contract_columns(): void
    {
        $this->assertTrue(Schema::hasColumns('hypotheses', [
            'id', 'scan_id', 'target_id', 'class', 'method', 'path', 'point', 'key', 'actor', 'oracle', 'action_class',
            'expected', 'rationale', 'angle', 'status', 'reason', 'attempts', 'parent_id', 'cost_requests', 'created_at', 'updated_at',
        ]));
    }

    public function test_new_hypothesis_starts_pending_with_zero_counters(): void
    {
        $scan = $this->scan();
        $hypothesis = $this->hypothesis($scan);

        $this->assertSame(Hypothesis::PENDENTE, $hypothesis->status);
        $this->assertSame(0, $hypothesis->attempts);
        $this->assertSame(0, $hypothesis->cost_requests);

        $fresh = $hypothesis->fresh();
        $this->assertSame('pendente', $fresh->status);
        $this->assertSame(0, $fresh->attempts);
        $this->assertSame(0, $fresh->cost_requests);
        $this->assertNull($fresh->reason);
        $this->assertTrue($fresh->scan->is($scan));
    }

    public function test_mark_updates_status_and_reason(): void
    {
        $hypothesis = $this->hypothesis($this->scan());

        $result = $hypothesis->mark(Hypothesis::CONFIRMADO, 'Conta B leu o canário da conta A duas vezes.');

        $this->assertSame($hypothesis, $result);
        $fresh = $hypothesis->fresh();
        $this->assertSame('confirmado', $fresh->status);
        $this->assertSame('Conta B leu o canário da conta A duas vezes.', $fresh->reason);

        $hypothesis->mark(Hypothesis::SEM_ORCAMENTO);
        $this->assertSame('sem_orcamento', $hypothesis->fresh()->status);
        $this->assertNull($hypothesis->fresh()->reason);
    }

    public function test_mark_rejects_unknown_status_without_touching_the_row(): void
    {
        $hypothesis = $this->hypothesis($this->scan());

        try {
            $hypothesis->mark('provado', 'qualquer');
            $this->fail('Status inválido deveria ser rejeitado.');
        } catch (InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }

        $this->assertSame('pendente', $hypothesis->fresh()->status);
        $this->assertNull($hypothesis->fresh()->reason);
    }

    public function test_saving_with_unknown_status_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->hypothesis($this->scan(), ['status' => 'achado']);
    }

    public function test_statuses_constant_lists_the_contract_statuses(): void
    {
        $this->assertSame(['pendente', 'confirmado', 'refutado', 'bloqueado', 'sem_orcamento', 'rejeitado'], Hypothesis::STATUSES);
    }

    public function test_pending_scope_and_cascade_on_scan_delete(): void
    {
        $scan = $this->scan();
        $other = $this->scan();
        $open = $this->hypothesis($scan);
        $this->hypothesis($scan)->mark(Hypothesis::REFUTADO, 'Resposta 403 para a conta B.');
        $this->hypothesis($scan, ['parent_id' => $open->id, 'angle' => 'trocar id no corpo'])->mark(Hypothesis::BLOQUEADO, 'Proxy recusou.');
        $this->hypothesis($other);

        $this->assertSame([$open->id], Hypothesis::where('scan_id', $scan->id)->pending()->pluck('id')->all());
        $this->assertSame(2, Hypothesis::pending()->count());

        $scan->delete();

        $this->assertSame(1, Hypothesis::count());
        $this->assertSame($other->id, Hypothesis::first()->scan_id);
    }
}
