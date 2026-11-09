<?php

namespace App\Providers;

use Illuminate\Support\Facades\Gate;
use Laravel\Horizon\Horizon;
use Laravel\Horizon\HorizonApplicationServiceProvider;

class HorizonServiceProvider extends HorizonApplicationServiceProvider
{
    protected function authorization(): void
    {
        $this->gate();

        Horizon::auth(fn ($request) => Gate::forUser($request->user())->allows('viewHorizon'));
    }

    protected function gate(): void
    {
        Gate::define('viewHorizon', fn ($user) => $user->is_admin && ! $user->suspended_at);
    }
}
