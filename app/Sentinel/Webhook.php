<?php

namespace App\Sentinel;

use Illuminate\Support\Facades\Http;

final class Webhook
{
    public static function acceptable(?string $url): bool
    {
        if ($url === null || $url === '') {
            return true;
        }
        $parts = parse_url($url);
        $host = strtolower($parts['host'] ?? '');
        if (($parts['scheme'] ?? null) !== 'https' || $host === '' || isset($parts['user']) || isset($parts['pass'])
            || filter_var($host, FILTER_VALIDATE_IP) || ! str_contains($host, '.')) {
            return false;
        }

        return true;
    }

    public static function publicHost(string $url): bool
    {
        return self::address($url) !== null;
    }

    public static function address(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);
        $addresses = is_string($host) ? (gethostbynamel($host) ?: []) : [];
        if ($addresses === [] || array_filter($addresses, fn ($ip) => ! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE))) {
            return null;
        }

        return $addresses[0];
    }

    public static function send(string $url, array $payload): void
    {
        if (! self::acceptable($url) || ($ip = self::address($url)) === null) {
            throw new \RuntimeException('Webhook recusado: o destino não é um endereço HTTPS público.');
        }
        $host = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT) ?: 443;
        try {
            $response = Http::connectTimeout(3)->timeout(5)->withoutRedirecting()
                ->withOptions(['curl' => [CURLOPT_RESOLVE => ["{$host}:{$port}:{$ip}"]]])
                ->post($url, $payload);
        } catch (\Throwable) {
            throw new \RuntimeException('Webhook inacessível.');
        }
        if (! $response->successful()) {
            throw new \RuntimeException('Webhook respondeu HTTP '.$response->status().'.');
        }
    }
}
