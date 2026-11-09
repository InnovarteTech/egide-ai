<?php

namespace App\Models;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Database\Eloquent\Model;

class Platform extends Model
{
    protected $table = 'platform_settings';

    protected $guarded = [];

    protected $hidden = ['ai_key'];

    protected function casts(): array
    {
        return ['ai_key' => 'encrypted', 'ai_daily_limit' => 'integer'];
    }

    public static function current(): self
    {
        return static::query()->find(1) ?? static::query()->firstOrCreate(['id' => 1], ['ai_provider' => 'lab', 'ai_daily_limit' => 20]);
    }

    public function key(): ?string
    {
        try {
            return $this->ai_key;
        } catch (DecryptException) {
            return null;
        }
    }
}
