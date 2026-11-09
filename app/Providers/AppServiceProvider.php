<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        RateLimiter::for('sentinela', fn (Request $request) => Limit::perMinute(600)
            ->by(hash('sha256', (string) $request->bearerToken()).'|'.$request->ip()));
        RateLimiter::for('egide-ip', fn (Request $request) => Limit::perMinute(1200)->by($request->ip()));
        RateLimiter::for('egide-api', fn (Request $request) => Limit::perMinute(30)
            ->by(hash('sha256', (string) $request->bearerToken())));
    }
}
