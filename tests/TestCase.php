<?php

namespace Tests;

use App\Models\Platform;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function platformEngine(string $provider = 'anthropic', string $model = 'test-model', string $key = 'test-key', int $limit = 20): void
    {
        Platform::current()->update(['ai_provider' => $provider, 'ai_model' => $model, 'ai_key' => $key, 'ai_daily_limit' => $limit]);
    }
}
