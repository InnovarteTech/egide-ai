<?php

namespace App\Http\Controllers;

use App\Models\ApiToken;
use App\Models\Target;
use App\Models\Workspace;
use App\Sentinel\Webhook;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class IntegrationController extends Controller
{
    public function createToken(Request $request)
    {
        $data = $request->validate(['name' => 'required|string|max:80']);
        abort_if(ApiToken::where('user_id', $request->user()->id)->count() >= 10, 422, 'Limite de tokens atingido.');
        $token = ApiToken::issue();
        ApiToken::create([
            'user_id' => $request->user()->id, 'name' => $data['name'],
            'token_hash' => ApiToken::hash($token), 'prefix' => substr($token, 0, 14),
        ]);

        return back()->with('api_token', $token)->with('notice', 'Token criado. Copie agora: ele não será exibido de novo.');
    }

    public function revokeToken(Request $request, ApiToken $token)
    {
        abort_unless($token->user_id === $request->user()->id, 404);
        $token->delete();

        return back()->with('notice', 'Token revogado.');
    }

    public function webhook(Request $request)
    {
        $data = $request->validate(['webhook_url' => 'nullable|string|max:500']);
        $url = trim((string) ($data['webhook_url'] ?? '')) ?: null;
        if (! Webhook::acceptable($url)) {
            throw ValidationException::withMessages(['webhook_url' => 'Use uma URL HTTPS de um domínio público, sem usuário e senha.']);
        }
        Workspace::firstOrCreate(['user_id' => $request->user()->id], ['name' => $request->user()->name])
            ->update(['webhook_url' => $url]);

        return back()->with('notice', $url ? 'Webhook de sessões salvo.' : 'Webhook de sessões removido.');
    }

    public function schedule(Request $request, Target $target)
    {
        abort_unless($target->user_id === $request->user()->id, 404);
        $data = $request->validate(['schedule' => 'required|in:off,daily,weekly']);
        if ($data['schedule'] !== 'off' && ! $target->verified_at) {
            throw ValidationException::withMessages(['schedule' => 'Verifique o domínio antes de agendar.']);
        }
        $target->update(['schedule' => $data['schedule'], 'next_run_at' => $data['schedule'] === 'off' ? null : now()]);

        return back()->with('notice', $data['schedule'] === 'off' ? 'Agenda desligada.' : 'Agenda ativada. A primeira sessão entra na fila em até 15 minutos.');
    }
}
