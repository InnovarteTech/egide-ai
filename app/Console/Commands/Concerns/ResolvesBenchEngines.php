<?php

namespace App\Console\Commands\Concerns;

use App\Models\Platform;
use App\Security\Engine;

trait ResolvesBenchEngines
{
    private function engines(): ?array
    {
        $list = $this->option('provedores');
        if (! is_string($list) || trim($list) === '') {
            if (! $this->option('agente')) {
                return ['lab' => null];
            }
            $engine = Engine::platform();
            if ($engine === null) {
                $this->error('O motor de IA da plataforma ainda não foi configurado no Super admin.');

                return null;
            }

            return [$engine['provider'] => $engine];
        }
        $model = $this->option('modelo');
        $platform = Platform::current();
        $engines = [];
        foreach (array_filter(array_map('trim', explode(',', $list))) as $provider) {
            if ($provider === 'lab') {
                $engines['lab'] = null;

                continue;
            }
            if (! in_array($provider, Engine::HOSTED, true)) {
                $this->error("Provedor desconhecido: {$provider}. Use lab ou um de: ".implode(', ', Engine::HOSTED).'.');

                return null;
            }
            $key = env('EGIDE_BENCH_'.strtoupper($provider).'_KEY') ?: ($platform->ai_provider === $provider ? $platform->key() : null);
            if (! $key) {
                $this->error("Sem chave para {$provider}: configure-a no Super admin como provedor atual ou defina EGIDE_BENCH_".strtoupper($provider).'_KEY.');

                return null;
            }
            $engines[$provider] = [
                'provider' => $provider,
                'model' => is_string($model) && $model !== '' ? $model : $platform->ai_model,
                'nav_model' => $platform->ai_nav_model ?: null,
                'key' => $key,
            ];
        }

        return $engines;
    }

    private function integer(string $option, int $min, int $max): ?int
    {
        $value = filter_var($this->option($option), FILTER_VALIDATE_INT, ['options' => ['min_range' => $min, 'max_range' => $max]]);
        if ($value === false) {
            $this->error("Informe --{$option} com um número inteiro entre {$min} e {$max}.");

            return null;
        }

        return $value;
    }
}
