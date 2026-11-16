<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use InvalidArgumentException;

class Hypothesis extends Model
{
    public const PENDENTE = 'pendente';

    public const CONFIRMADO = 'confirmado';

    public const REFUTADO = 'refutado';

    public const BLOQUEADO = 'bloqueado';

    public const SEM_ORCAMENTO = 'sem_orcamento';

    public const REJEITADO = 'rejeitado';

    public const STATUSES = [
        self::PENDENTE,
        self::CONFIRMADO,
        self::REFUTADO,
        self::BLOQUEADO,
        self::SEM_ORCAMENTO,
        self::REJEITADO,
    ];

    protected $table = 'hypotheses';

    protected $guarded = [];

    protected $attributes = [
        'status' => self::PENDENTE,
        'attempts' => 0,
        'cost_requests' => 0,
    ];

    protected function casts(): array
    {
        return [
            'target_id' => 'integer',
            'parent_id' => 'integer',
            'attempts' => 'integer',
            'cost_requests' => 'integer',
        ];
    }

    protected static function booted(): void
    {
        static::saving(function (Hypothesis $hypothesis): void {
            self::guardStatus((string) $hypothesis->status);
        });
    }

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    public function parent(): BelongsTo
    {
        return $this->belongsTo(self::class, 'parent_id');
    }

    public function scopePending(Builder $query): Builder
    {
        return $query->where('status', self::PENDENTE);
    }

    public function mark(string $status, ?string $reason = null): static
    {
        self::guardStatus($status);

        $this->forceFill(['status' => $status, 'reason' => $reason])->save();

        return $this;
    }

    private static function guardStatus(string $status): void
    {
        if (! in_array($status, self::STATUSES, true)) {
            throw new InvalidArgumentException("Status de hipótese inválido: {$status}.");
        }
    }
}
