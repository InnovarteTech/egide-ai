<?php

namespace App\Security;

use App\Models\Platform;
use App\Models\Scan;
use App\Models\User;

final class Engine
{
    public const HOSTED = ['anthropic', 'openai', 'openrouter'];

    public static function providers(): array
    {
        return collect(config('egide.providers'))
            ->filter(fn ($label, $key) => $key === 'lab' || in_array($key, self::HOSTED, true)
                || in_array($key, Planner::availableLocal(), true))
            ->all();
    }

    public static function platform(bool $external = false): ?array
    {
        $platform = Platform::current();
        $provider = $platform->ai_provider;
        if (isset(Planner::LOCAL[$provider])) {
            return Planner::localProvider($external, $provider) ? self::local($provider, $platform->ai_model) : null;
        }
        $key = $platform->key();
        if (in_array($provider, self::HOSTED, true) && filled($key) && filled($platform->ai_model)) {
            return ['provider' => $provider, 'model' => $platform->ai_model, 'nav_model' => $platform->ai_nav_model ?: null, 'key' => $key];
        }

        return null;
    }

    public static function usedToday(int $userId): int
    {
        return Scan::where('user_id', $userId)->where('provider', '!=', 'lab')
            ->where('created_at', '>=', now()->startOfDay())
            ->where(fn ($query) => $query->whereIn('status', ['queued', 'running'])->orWhere('request_count', '>', 0))
            ->count();
    }

    public static function limitReached(User $user): ?string
    {
        if ($user->is_admin) {
            return null;
        }
        $limit = Platform::current()->ai_daily_limit;

        return self::usedToday($user->id) >= $limit
            ? "Você atingiu o limite de {$limit} sessões com IA por hoje. Ele volta amanhã."
            : null;
    }

    private static function local(string $provider, ?string $model): array
    {
        return [
            'provider' => $provider,
            'model' => $provider === 'claude_local' ? ($model ?: config('egide.claude_model')) : null,
            'nav_model' => null,
            'key' => null,
        ];
    }
}
