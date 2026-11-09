<?php

use App\Http\Middleware\BlockDemoWrites;
use App\Http\Middleware\EnsureActive;
use App\Http\Middleware\EnsureAdmin;
use App\Http\Middleware\HandleInertiaRequests;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->trustProxies(at: array_map('trim', explode(',', (string) env('EGIDE_TRUSTED_PROXIES', '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'))));
        $middleware->web(append: [HandleInertiaRequests::class]);
        $middleware->alias(['admin' => EnsureAdmin::class, 'active' => EnsureActive::class, 'demo.readonly' => BlockDemoWrites::class]);
        $middleware->trimStrings(except: ['password_a', 'password_b', 'api_key']);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->dontFlash(['password_a', 'password_b', 'marker_a', 'marker_b', 'api_key']);
    })->create();
