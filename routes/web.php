<?php

use App\Http\Controllers\AccessController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\ConsoleController;
use App\Http\Controllers\EvidenceController;
use App\Http\Controllers\IntegrationController;
use App\Http\Controllers\SentinelController;
use App\Http\Controllers\SurfaceController;
use Illuminate\Support\Facades\Route;

Route::middleware('guest')->group(function (): void {
    Route::get('/entrar', [AccessController::class, 'form'])->name('login');
    Route::get('/cadastro', [AccessController::class, 'form'])->name('register');
    Route::post('/entrar', [AccessController::class, 'login'])->middleware('throttle:6,1');
    Route::post('/cadastro', [AccessController::class, 'register'])->middleware('throttle:4,1');
    Route::post('/laboratorio/entrar', [AccessController::class, 'demo'])->middleware('throttle:6,1');
});

Route::middleware(['auth', 'active', 'admin'])->prefix('admin')->group(function (): void {
    Route::get('/', [AdminController::class, 'index']);
    Route::post('/parar-tudo', [AdminController::class, 'stopAll']);
    Route::post('/pausa', [AdminController::class, 'pause']);
    Route::put('/motor', [AdminController::class, 'saveEngine']);
    Route::post('/motor/testar', [AdminController::class, 'testEngine'])->middleware('throttle:6,1');
    Route::post('/sessoes/{scan}/encerrar', [AdminController::class, 'stop']);
    Route::post('/usuarios/{user}/suspensao', [AdminController::class, 'suspend']);
});

Route::middleware(['auth', 'active'])->group(function (): void {
    Route::post('/sair', [AccessController::class, 'logout']);
    Route::get('/', [ConsoleController::class, 'index']);
    Route::permanentRedirect('/ativos', '/ambientes');
    Route::get('/ambientes', [ConsoleController::class, 'assets']);
    Route::post('/ambientes', [ConsoleController::class, 'createTarget'])->middleware('throttle:8,1')->middleware('demo.readonly');
    Route::put('/ambientes/{target}', [ConsoleController::class, 'updateTarget'])->middleware('throttle:8,1')->middleware('demo.readonly');
    Route::delete('/ambientes/{target}', [ConsoleController::class, 'deleteTarget'])->middleware('throttle:8,1')->middleware('demo.readonly');
    Route::post('/ambientes/{target}/verificar', [ConsoleController::class, 'verifyTarget'])->middleware('throttle:8,1')->middleware('demo.readonly');
    Route::post('/ambientes/{target}/superficie', [SurfaceController::class, 'store'])->middleware('throttle:8,1')->middleware('demo.readonly');
    Route::delete('/ambientes/{target}/superficie', [SurfaceController::class, 'destroy'])->middleware('throttle:8,1')->middleware('demo.readonly');
    Route::get('/sessoes', [ConsoleController::class, 'sessions']);
    Route::get('/sessoes/nova', [ConsoleController::class, 'sessionForm']);
    Route::post('/sessoes', [ConsoleController::class, 'createScan'])->middleware('throttle:8,1');
    Route::get('/sessoes/{scan}', [ConsoleController::class, 'showScan']);
    Route::get('/sessoes/{scan}/eventos', [ConsoleController::class, 'feed']);
    Route::get('/sessoes/{scan}/imagem', [ConsoleController::class, 'frame']);
    Route::get('/achados/{finding}/imagem', [EvidenceController::class, 'findingImage']);
    Route::get('/sessoes/{scan}/relatorio', [ConsoleController::class, 'report']);
    Route::get('/sessoes/{scan}/relatorio/imprimir', [ConsoleController::class, 'printReport']);
    Route::post('/sessoes/{scan}/encerrar', [ConsoleController::class, 'stop']);
    Route::get('/achados', [ConsoleController::class, 'findings']);
    Route::post('/configuracoes/tokens', [IntegrationController::class, 'createToken'])->middleware('throttle:6,1')->middleware('demo.readonly');
    Route::delete('/configuracoes/tokens/{token}', [IntegrationController::class, 'revokeToken'])->middleware('demo.readonly');
    Route::put('/configuracoes/webhook', [IntegrationController::class, 'webhook'])->middleware('throttle:12,1')->middleware('demo.readonly');
    Route::put('/ambientes/{target}/agenda', [IntegrationController::class, 'schedule'])->middleware('throttle:12,1')->middleware('demo.readonly');
    Route::get('/sentinela', [SentinelController::class, 'index']);
    Route::post('/sentinela', [SentinelController::class, 'store'])->middleware('throttle:8,1')->middleware('demo.readonly');
    Route::get('/sentinela/{monitor}', [SentinelController::class, 'show']);
    Route::put('/sentinela/{monitor}', [SentinelController::class, 'update'])->middleware('throttle:12,1')->middleware('demo.readonly');
    Route::post('/sentinela/{monitor}/chave', [SentinelController::class, 'rotate'])->middleware('throttle:6,1')->middleware('demo.readonly');
    Route::delete('/sentinela/{monitor}', [SentinelController::class, 'destroy'])->middleware('demo.readonly');
    Route::post('/alertas/{alert}/status', [SentinelController::class, 'resolve'])->middleware('demo.readonly');
    Route::get('/configuracoes', [ConsoleController::class, 'settings']);
    Route::put('/configuracoes', [ConsoleController::class, 'saveSettings']);
});
