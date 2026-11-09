<?php

namespace App\Security;

use App\Models\Scan;
use App\Models\Workspace;

final class Demo
{
    public const API_PROVIDERS = ['anthropic', 'openai', 'openrouter'];

    public static function engineReady(): bool
    {
        $provider = config('egide.demo_provider');

        return in_array($provider, self::API_PROVIDERS, true) && filled(config('egide.demo_api_key')) && filled(config('egide.demo_model'));
    }

    public static function provider(): ?string
    {
        $provider = config('egide.demo_provider');
        if (isset(Planner::LOCAL[$provider])) {
            return app()->environment('local') ? Planner::localProvider(false, $provider) : null;
        }

        return self::engineReady() ? $provider : null;
    }

    public static function limitReached(Workspace $workspace): ?string
    {
        $today = now()->startOfDay();
        if (Scan::where('user_id', $workspace->user_id)->whereIn('status', ['queued', 'running'])->exists()) {
            return 'Aguarde a sessão atual terminar para iniciar outra.';
        }
        $own = Scan::where('user_id', $workspace->user_id)->where('created_at', '>=', $today)->count();
        if ($own >= config('egide.demo_daily_per_user')) {
            return 'Você atingiu o limite de sessões da demonstração por hoje. Crie uma conta para continuar.';
        }
        $total = Scan::whereIn('user_id', Workspace::where('demo', true)->select('user_id'))->where('provider', '!=', 'lab')
            ->where('created_at', '>=', $today)->count();
        if ($total >= config('egide.demo_daily_total')) {
            return 'A demonstração pública atingiu o limite diário de sessões. Tente novamente amanhã.';
        }

        return null;
    }

    public static function accountsFull(): bool
    {
        return Workspace::where('demo', true)->count() >= config('egide.demo_max_accounts');
    }
}
