<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Workspace extends Model
{
    protected $guarded = [];

    protected $hidden = ['api_key', 'webhook_url'];

    protected function casts(): array
    {
        return ['api_key' => 'encrypted', 'webhook_url' => 'encrypted', 'demo' => 'boolean'];
    }
}
