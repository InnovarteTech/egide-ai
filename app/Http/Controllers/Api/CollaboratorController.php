<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\CollaboratorHit;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class CollaboratorController extends Controller
{
    public function ingest(Request $request, string $token)
    {
        if (CollaboratorHit::where('token', $token)->count() >= 50) {
            return response('', 204);
        }
        CollaboratorHit::create([
            'token' => $token,
            'method' => substr($request->method(), 0, 10),
            'source_ip' => $request->ip(),
            'path' => Str::limit($request->getRequestUri(), 500, ''),
            'user_agent' => Str::limit((string) $request->userAgent(), 250, ''),
            'body_excerpt' => Str::limit(substr((string) $request->getContent(), 0, 2000), 500, ''),
            'received_at' => now(),
        ]);

        return response('', 204);
    }
}
