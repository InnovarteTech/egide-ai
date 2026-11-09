<?php

return [
    'runner_url' => env('EGIDE_RUNNER_URL', 'http://127.0.0.1:8791'),
    'runner_urls' => array_values(array_filter(array_map('trim', explode(',', (string) env('EGIDE_RUNNER_URLS', env('EGIDE_RUNNER_URL', 'http://127.0.0.1:8791')))))),
    'runner_token' => env('EGIDE_RUNNER_TOKEN'),
    'demo_access' => env('EGIDE_DEMO_ACCESS', false),
    'demo_daily_per_user' => (int) env('EGIDE_DEMO_DAILY_PER_USER', 5),
    'demo_daily_total' => (int) env('EGIDE_DEMO_DAILY_TOTAL', 120),
    'demo_ttl_hours' => (int) env('EGIDE_DEMO_TTL_HOURS', 24),
    'demo_max_accounts' => (int) env('EGIDE_DEMO_MAX_ACCOUNTS', 300),
    'demo_accounts_per_ip' => (int) env('EGIDE_DEMO_ACCOUNTS_PER_IP', 10),
    'codex_binary' => env('EGIDE_CODEX_BINARY'),
    'codex_external' => env('EGIDE_CODEX_EXTERNAL', false),
    'claude_binary' => env('EGIDE_CLAUDE_BINARY'),
    'claude_external' => env('EGIDE_CLAUDE_EXTERNAL', false),
    'claude_model' => env('EGIDE_CLAUDE_MODEL', 'sonnet'),
    'local_targets' => env('EGIDE_LOCAL_TARGETS', false),
    'horizon_operator' => env('EGIDE_HORIZON_OPERATOR'),
    'providers' => [
        'lab' => 'Roteiro do laboratório',
        'openai' => 'OpenAI',
        'anthropic' => 'Claude',
        'openrouter' => 'OpenRouter',
        'claude_local' => 'Claude local (Claude Code)',
        'codex' => 'Codex local',
    ],
];
