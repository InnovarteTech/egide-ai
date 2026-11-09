<?php

use App\Http\Controllers\Api\IngestController;
use App\Http\Controllers\Api\ScanApiController;
use App\Http\Middleware\AuthenticateApiToken;
use Illuminate\Support\Facades\Route;

Route::post('/sentinela/eventos', [IngestController::class, 'store'])->middleware(['throttle:egide-ip', 'throttle:sentinela']);

Route::prefix('v1')->middleware(['throttle:egide-ip', AuthenticateApiToken::class, 'throttle:egide-api'])->group(function (): void {
    Route::get('/ativos', [ScanApiController::class, 'targets']);
    Route::post('/sessoes', [ScanApiController::class, 'store']);
    Route::get('/sessoes/{scan}', [ScanApiController::class, 'show']);
});
