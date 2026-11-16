<?php

namespace App\Models;

use App\Security\Severity;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class Finding extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['evidence' => 'array', 'cvss_score' => 'float'];
    }

    protected static function booted(): void
    {
        static::creating(function (Finding $finding): void {
            $impact = $finding->evidence['impact'] ?? null;
            $rated = is_array($impact) ? Severity::rate($impact) : null;

            if ($rated !== null && $rated['score'] > 0) {
                $finding->severity = $rated['severity'];
                $finding->cvss_vector = $rated['vector'];
                $finding->cvss_score = $rated['score'];
            } elseif (blank($finding->cvss_vector)) {
                $fallback = Severity::fromSeverity((string) $finding->severity);
                $finding->cvss_vector = $fallback['vector'];
                $finding->cvss_score = $fallback['score'];
            }

            if (blank($finding->track)) {
                $finding->track = 'achado';
            }
        });
    }

    public function scopeAchados(Builder $query): Builder
    {
        return $query->where('track', 'achado');
    }

    public function scopeObservacoes(Builder $query): Builder
    {
        return $query->where('track', 'observacao');
    }
}
