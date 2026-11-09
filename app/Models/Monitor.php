<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Str;

class Monitor extends Model
{
    protected $guarded = [];

    protected $hidden = ['key_hash', 'webhook_url'];

    protected function casts(): array
    {
        return ['last_event_at' => 'datetime', 'webhook_url' => 'encrypted'];
    }

    public static function issueKey(): string
    {
        return 'esc_'.Str::random(40);
    }

    public static function hashKey(string $key): string
    {
        return hash('sha256', $key);
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function events(): HasMany
    {
        return $this->hasMany(MonitorEvent::class);
    }

    public function alerts(): HasMany
    {
        return $this->hasMany(Alert::class);
    }
}
