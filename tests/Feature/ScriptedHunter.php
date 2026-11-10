<?php

namespace Tests\Feature;

use App\Models\Scan;
use App\Security\Hunter;

class ScriptedHunter extends Hunter
{
    public array $contexts = [];

    public function __construct(private array $script)
    {
        parent::__construct();
    }

    public function next(Scan $scan, array $context): array
    {
        $this->contexts[] = $context;

        return array_shift($this->script) ?? ['done' => true, 'reason' => 'roteiro concluído', 'experiment' => self::step('xss', '/', 'q', '{MARKER}')['experiment']];
    }

    public static function step(string $technique, string $path, ?string $key, string $payload, ?string $false = null): array
    {
        return ['done' => false, 'reason' => '', 'experiment' => [
            'method' => 'GET', 'path' => $path, 'point' => 'query', 'key' => $key, 'technique' => $technique,
            'payload' => $payload, 'false_payload' => $false, 'rationale' => 'teste roteirizado',
        ]];
    }
}
