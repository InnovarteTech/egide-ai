<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Monitor;
use App\Sentinel\Ingest;
use Illuminate\Http\Request;

class IngestController extends Controller
{
    public function store(Request $request, Ingest $ingest)
    {
        $key = (string) $request->bearerToken();
        $monitor = str_starts_with($key, 'esc_') ? Monitor::with('user')->where('key_hash', Monitor::hashKey($key))->first() : null;
        if (! $monitor || ! $monitor->user || $monitor->user->suspended_at) {
            return response()->json(['error' => 'Chave do Sentinela inválida.'], 401);
        }

        $data = $request->validate(['events' => 'required|array|min:1|max:100']);

        return response()->json($ingest->accept($monitor, $data['events']), 202);
    }
}
