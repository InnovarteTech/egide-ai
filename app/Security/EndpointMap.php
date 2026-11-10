<?php

namespace App\Security;

final class EndpointMap
{
    public static function qualify(?string $host, ?string $front, string $path): string
    {
        if ($host === null || $host === $front) {
            return $path;
        }

        return 'https://'.$host.$path;
    }

    public static function merge(array $inventory, array $event): array
    {
        $method = strtoupper($event['method'] ?? 'GET');
        [$path, $query] = array_pad(explode('?', (string) ($event['path'] ?? '/'), 2), 2, '');
        $key = $method.' '.$path;
        parse_str($query, $params);

        $entry = $inventory[$key] ?? [
            'method' => $method, 'path' => $path, 'params' => [], 'body' => [],
            'auth' => false, 'seen_in' => $event['seen_in'] ?? 'xhr',
        ];
        $entry['params'] = array_values(array_unique([...$entry['params'], ...array_keys($params)]));
        $entry['body'] = array_values(array_unique([...$entry['body'], ...array_keys((array) ($event['body'] ?? []))]));
        $entry['auth'] = $entry['auth'] || (bool) ($event['auth'] ?? false);
        $inventory[$key] = $entry;

        return $inventory;
    }

    public static function fromBundle(string $js, string $origin): array
    {
        preg_match_all('~["\'`](/[A-Za-z0-9_./\-]*)["\'`]~', $js, $matches);
        $routes = [];
        foreach ($matches[1] as $raw) {
            if (preg_match('~\.(css|js|mjs|png|jpe?g|gif|svg|webp|woff2?|ttf|ico|map|json|txt)$~i', $raw)) {
                continue;
            }
            if (! str_contains($raw, '/api') && ! preg_match('~^/(v\d+|graphql|auth|admin)\b~', $raw)) {
                continue;
            }
            $route = rtrim($raw, '/');
            if (str_ends_with($raw, '/')) {
                $route .= '/{id}';
            }
            $route = preg_replace('~/\d+(?=/|$)~', '/{id}', $route);
            if ($route !== '' && $route !== '/api') {
                $routes[$route] = true;
            }
        }

        return array_keys($routes);
    }
}
