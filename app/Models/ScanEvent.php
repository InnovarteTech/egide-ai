<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ScanEvent extends Model
{
    const UPDATED_AT = null;

    protected $guarded = [];

    protected function casts(): array
    {
        return ['data' => 'array'];
    }
}
