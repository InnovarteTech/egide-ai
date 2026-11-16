<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Scan extends Model
{
    use HasUuids;

    protected $guarded = [];

    protected $hidden = ['engine_key', 'credentials'];

    protected function casts(): array
    {
        return [
            'scope' => 'array',
            'summary' => 'array',
            'coverage' => 'array',
            'regression' => 'boolean',
            'engine_key' => 'encrypted',
            'credentials' => 'encrypted:array',
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
            'stop_requested_at' => 'datetime',
        ];
    }

    public function events(): HasMany
    {
        return $this->hasMany(ScanEvent::class);
    }

    public function target(): BelongsTo
    {
        return $this->belongsTo(Target::class);
    }

    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }

    public function hypotheses(): HasMany
    {
        return $this->hasMany(Hypothesis::class);
    }

    public function event(string $type, string $title, ?string $detail = null, ?array $data = null): void
    {
        $this->events()->create(compact('type', 'title', 'detail', 'data'));
    }
}
