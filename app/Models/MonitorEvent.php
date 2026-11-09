<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MonitorEvent extends Model
{
    public const TYPES = ['login_failed', 'login_succeeded', 'access_denied', 'password_reset'];

    public $timestamps = false;

    protected $guarded = [];

    protected function casts(): array
    {
        return ['occurred_at' => 'datetime'];
    }
}
