<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Target extends Model
{
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    protected $guarded = [];

    protected $hidden = ['credentials'];

    protected function casts(): array
    {
        return ['verified_at' => 'datetime', 'next_run_at' => 'datetime', 'rules' => 'array', 'denied' => 'array', 'credentials' => 'encrypted:array'];
    }
}
