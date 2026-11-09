<?php

namespace App\Http\Middleware;

use App\Models\ApiToken;
use Closure;
use Illuminate\Http\Request;

class AuthenticateApiToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = (string) $request->bearerToken();
        $record = str_starts_with($token, 'escapi_') ? ApiToken::with('user')->where('token_hash', ApiToken::hash($token))->first() : null;
        if (! $record || ! $record->user || $record->user->suspended_at) {
            return response()->json(['error' => 'Token de API inválido.'], 401);
        }
        if (! $record->last_used_at || $record->last_used_at->lt(now()->subMinute())) {
            $record->forceFill(['last_used_at' => now()])->save();
        }
        $request->setUserResolver(fn () => $record->user);

        return $next($request);
    }
}
