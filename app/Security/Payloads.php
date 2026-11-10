<?php

namespace App\Security;

final class Payloads
{
    public const CALLBACK = '__CALLBACK__';

    public static function marker(string $prefix): string
    {
        return $prefix.strtolower(bin2hex(random_bytes(4)));
    }

    public static function for(string $class, string $point, array $context = []): array
    {
        return match ($class) {
            'xss' => self::xss($context['context'] ?? 'html'),
            'sqli_time' => self::sqliTime(),
            'ssrf' => self::ssrf(),
            default => [],
        };
    }

    private static function xss(string $context): array
    {
        $marker = self::marker('egideXSS');
        $value = match ($context) {
            'js' => '</script><'.$marker.'>',
            'attr' => '"><'.$marker.'>',
            default => '"><'.$marker.'>',
        };

        return [['value' => $value, 'oracle' => 'injectionReflectedAssess', 'marker' => $marker]];
    }

    private static function sqliTime(): array
    {
        return array_map(fn ($value) => ['value' => $value, 'oracle' => 'injectionTimeAssess', 'marker' => null], [
            "1' AND SLEEP(5)-- -",
            "1'||pg_sleep(5)--",
            '1);SELECT pg_sleep(5)--',
        ]);
    }

    private static function ssrf(): array
    {
        return [['value' => self::CALLBACK, 'oracle' => 'ssrfAssess', 'marker' => null]];
    }
}
