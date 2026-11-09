<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Scan;
use App\Models\Target;
use App\Security\Launcher;
use Illuminate\Http\Request;
use RuntimeException;

class ScanApiController extends Controller
{
    public function targets(Request $request)
    {
        return response()->json(['ativos' => Target::where('user_id', $request->user()->id)->whereNotNull('verified_at')
            ->get(['id', 'name', 'origin', 'schedule'])]);
    }

    public function store(Request $request, Launcher $launcher)
    {
        $data = $request->validate(['ativo' => 'required|integer', 'orcamento' => 'nullable|integer|min:10|max:180']);
        $target = Target::where('user_id', $request->user()->id)->find($data['ativo']);
        if (! $target) {
            return response()->json(['error' => 'Ativo não encontrado.'], 404);
        }
        try {
            $scan = $launcher->external($target, 'api', $data['orcamento'] ?? 80);
        } catch (RuntimeException $error) {
            return response()->json(['error' => $error->getMessage()], 409);
        }

        return response()->json($this->present($scan->fresh()), 202);
    }

    public function show(Request $request, string $scan)
    {
        $record = Scan::where('user_id', $request->user()->id)->find($scan);
        if (! $record) {
            return response()->json(['error' => 'Sessão não encontrada.'], 404);
        }

        return response()->json($this->present($record));
    }

    private function present(Scan $scan): array
    {
        $counts = $scan->findings()->get()->countBy('severity');

        return [
            'id' => $scan->id, 'ativo' => $scan->target_id, 'status' => $scan->status, 'fase' => $scan->phase,
            'resultado' => $scan->result, 'regressao' => $scan->regression, 'erro' => $scan->error,
            'risco' => $scan->summary['risk'] ?? null,
            'achados' => [
                'critical' => $counts['critical'] ?? 0, 'high' => $counts['high'] ?? 0,
                'medium' => $counts['medium'] ?? 0, 'low' => $counts['low'] ?? 0,
            ],
            'relatorio' => url('/sessoes/'.$scan->id.'/relatorio/imprimir'),
            'criada_em' => $scan->created_at?->toIso8601String(), 'concluida_em' => $scan->finished_at?->toIso8601String(),
        ];
    }
}
