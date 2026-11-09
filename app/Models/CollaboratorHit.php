<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class CollaboratorHit extends Model
{
    public $timestamps = false;

    protected $guarded = [];

    protected function casts(): array
    {
        return ['received_at' => 'datetime'];
    }
}
