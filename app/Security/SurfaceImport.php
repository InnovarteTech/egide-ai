<?php

namespace App\Security;

use InvalidArgumentException;
use Symfony\Component\Yaml\Yaml;

final class SurfaceImport
{
    public const MAX_BYTES = 5242880;

    public const MAX_ENDPOINTS = 600;

    public const MAX_NODES = 5000;

    private const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

    private const ASSET = '~\.(css|js|mjs|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|map|mp4|webm|mp3)$~i';

    private const UNKNOWN = 'Formato não reconhecido. Envie OpenAPI 3, Swagger 2, coleção do Postman (v2 ou v2.1) ou HAR.';

    private const NOTES = [
        'dropped' => 'Limite de '.self::MAX_ENDPOINTS.' rotas atingido: %d rotas ficaram de fora.',
        'invalid' => '%d rotas ignoradas por método ou caminho inválido.',
        'hostless' => '%d requisições sem endereço definido foram associadas à origem principal.',
        'truncated' => 'Esquemas muito aninhados: a leitura de campos parou no limite de 5.000 nós (%d ignorados).',
    ];

    private array $endpoints = [];

    private array $skipped = [];

    private array $warnings = [];

    private array $tally = ['dropped' => 0, 'invalid' => 0, 'hostless' => 0, 'truncated' => 0];

    private array $memo = [];

    private int $nodes = 0;

    private array $hosts;

    private function __construct(private array $doc, array $origins)
    {
        $this->hosts = array_values(array_filter(array_map(fn ($origin) => strtolower((string) parse_url((string) $origin, PHP_URL_HOST)), $origins)));
    }

    public static function parse(string $content, ?string $filename = null, array $origins = []): array
    {
        if (strlen($content) > self::MAX_BYTES) {
            throw new InvalidArgumentException('O arquivo passa do limite de 5 MB.');
        }
        $doc = self::decode($content, $filename);
        $import = new self($doc, $origins);
        $format = match (true) {
            is_scalar($doc['openapi'] ?? null) && str_starts_with((string) $doc['openapi'], '3') => $import->spec('openapi'),
            is_scalar($doc['swagger'] ?? null) && str_starts_with((string) $doc['swagger'], '2') => $import->spec('swagger'),
            is_array($doc['log']['entries'] ?? null) => $import->har($doc['log']['entries']),
            is_array($doc['item'] ?? null) && is_array($doc['info'] ?? null) => $import->postman($doc['item'], self::authed($doc['auth'] ?? null)),
            default => throw new InvalidArgumentException(self::UNKNOWN),
        };
        foreach (array_filter($import->tally) as $note => $count) {
            $import->warnings[] = sprintf(self::NOTES[$note], $count);
        }

        return ['endpoints' => array_values($import->endpoints), 'meta' => [
            'format' => $format, 'count' => count($import->endpoints),
            'skipped_hosts' => array_slice(array_keys($import->skipped), 0, 50), 'warnings' => $import->warnings,
        ]];
    }

    public static function merge(array $inventory, array $imported): array
    {
        foreach ($imported as $endpoint) {
            if (! is_array($endpoint) || ! is_string($endpoint['path'] ?? null)) {
                continue;
            }
            $method = strtoupper((string) ($endpoint['method'] ?? 'GET'));
            $path = EndpointMap::qualify($endpoint['host'] ?? null, null, $endpoint['path']);
            $key = $method.' '.$path;
            $source = $inventory[$key]['source'] ?? $endpoint['source'] ?? 'import';
            $inventory = EndpointMap::merge($inventory, [
                'method' => $method, 'path' => $path, 'auth' => (bool) ($endpoint['auth'] ?? false), 'seen_in' => 'import',
                'body' => array_fill_keys(array_filter((array) ($endpoint['body'] ?? []), 'is_string'), true),
            ]);
            $params = array_filter((array) ($endpoint['params'] ?? []), 'is_string');
            $inventory[$key]['params'] = array_values(array_unique([...$inventory[$key]['params'], ...$params]));
            $inventory[$key]['source'] = $source;
            if (! empty($endpoint['template']) || str_contains($endpoint['path'], '{')) {
                $inventory[$key]['template'] = true;
            }
        }

        return $inventory;
    }

    public static function path(string $raw, bool $concrete = false): ?string
    {
        $raw = preg_replace('~^[a-z][a-z0-9+.-]*://[^/?#]*~i', '', trim($raw));
        $segments = [];
        foreach (explode('/', preg_split('~[?#]~', $raw, 2)[0]) as $segment) {
            if (in_array(rawurldecode($segment), ['.', '..'], true)) {
                return null;
            }
            $segment = preg_replace('~\{\{[^{}]*\}\}|\{[^{}]*\}~', '{id}', $segment);
            $masked = preg_match('~^:[A-Za-z_]\w*$|^[0-9a-f]{40,}$|@~i', $segment)
                || (strlen($segment) >= 20 && preg_match('~^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[\w.=\~-]+$~', $segment));
            $record = preg_match('~^\d+$|^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$|^[0-9a-f]{16,}$~i', $segment);
            $segments[] = $masked || ($record && ! $concrete) ? '{id}' : $segment;
        }
        $path = '/'.implode('/', array_filter($segments, fn ($segment) => $segment !== ''));

        return strlen($path) <= 300 && preg_match("~^/[A-Za-z0-9._\~!$&'()*+,;=:@%{}/-]*$~D", $path) ? $path : null;
    }

    private static function decode(string $content, ?string $filename): array
    {
        $content = trim(preg_replace('/^\xEF\xBB\xBF/', '', $content));
        $doc = json_decode($content, true, 512);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $yaml = preg_match('~\.ya?ml$~i', (string) $filename) || preg_match('~^\s*(openapi|swagger)\s*:~m', $content);
            if (! class_exists(Yaml::class)) {
                throw new InvalidArgumentException($yaml
                    ? 'Este servidor não lê YAML. Converta o documento para JSON e envie novamente.'
                    : 'Não foi possível ler o arquivo. Envie um documento JSON válido.');
            }
            try {
                $doc = Yaml::parse($content);
            } catch (\Throwable) {
                throw new InvalidArgumentException('Não foi possível ler o arquivo. Envie um documento JSON ou YAML válido.');
            }
        }
        if (! is_array($doc) || array_is_list($doc)) {
            throw new InvalidArgumentException(self::UNKNOWN);
        }

        return $doc;
    }

    private function spec(string $source): string
    {
        $servers = $source === 'swagger'
            ? [[is_string($this->doc['host'] ?? null) ? strtolower(explode(':', $this->doc['host'])[0]) : null, is_string($this->doc['basePath'] ?? null) ? $this->doc['basePath'] : '']]
            : array_map(function (array $server): array {
                $url = preg_replace_callback('~\{([^{}]*)\}~', fn ($match) => (string) ($server['variables'][$match[1]]['default'] ?? ''), $server['url']);

                return preg_match('~^[a-z][a-z0-9+.-]*://~i', $url) ? [strtolower((string) parse_url($url, PHP_URL_HOST)) ?: null, (string) parse_url($url, PHP_URL_PATH)] : [null, $url];
            }, array_filter((array) ($this->doc['servers'] ?? []), fn ($server) => is_array($server) && is_string($server['url'] ?? null)));
        [$host, $base] = $this->base(array_values($servers));
        foreach ((array) ($this->doc['paths'] ?? []) as $route => $item) {
            $item = $this->deref($item);
            foreach (is_string($route) && is_array($item) ? $item : [] as $verb => $operation) {
                $method = strtoupper((string) $verb);
                if (! in_array($method, self::METHODS, true) || ! is_array($operation)) {
                    continue;
                }
                $parameters = array_filter(array_map(fn ($parameter) => $this->deref($parameter),
                    [...(array) ($item['parameters'] ?? []), ...(array) ($operation['parameters'] ?? [])]), 'is_array');
                $schemas = $source === 'swagger' ? array_filter($parameters, fn ($parameter) => ($parameter['in'] ?? null) === 'body')
                    : array_filter((array) ($this->deref($operation['requestBody'] ?? [])['content'] ?? []), 'is_array');
                $body = $this->named($parameters, 'formData');
                foreach (array_column($schemas, 'schema') as $schema) {
                    $body = [...$body, ...$this->fields($schema)];
                }
                $security = $operation['security'] ?? $this->doc['security'] ?? [];
                $secured = is_array($security) && array_filter($security, fn ($requirement) => is_array($requirement) && $requirement !== []);
                $this->add($method, $base.'/'.$route, $host, $this->named($parameters, 'query'), $body, (bool) $secured, $source);
            }
        }

        return $source;
    }

    private function postman(array $items, bool $auth, int $depth = 0): string
    {
        foreach ($depth > 20 ? [] : array_filter($items, 'is_array') as $item) {
            $inherited = isset($item['auth']) ? self::authed($item['auth']) : $auth;
            $request = is_string($item['request'] ?? null) ? ['url' => $item['request']] : $item['request'] ?? null;
            if (is_array($item['item'] ?? null) || ! is_array($request)) {
                $this->postman((array) ($item['item'] ?? []), $inherited, $depth + 1);

                continue;
            }
            $url = $request['url'] ?? '';
            $query = is_array($url) ? array_column(array_filter((array) ($url['query'] ?? []), 'is_array'), 'key') : [];
            if (is_array($url)) {
                $segments = array_map(fn ($part) => is_array($part) ? (string) ($part['value'] ?? '') : (string) $part, (array) ($url['path'] ?? []));
                $url = is_string($url['raw'] ?? null) ? $url['raw'] : implode('.', (array) ($url['host'] ?? [])).'/'.implode('/', $segments);
            }
            $url = preg_replace_callback('~^\{\{([^{}]*)\}\}~', fn ($match) => $this->variable($match[1]) ?? $match[0], trim((string) $url));
            $body = (array) ($request['body'] ?? []);
            $fields = match ($body['mode'] ?? null) {
                'raw' => self::textFields(preg_replace('~\{\{[^{}]*\}\}~', '0', (string) ($body['raw'] ?? '')), 'json'),
                'urlencoded', 'formdata' => array_column(array_filter((array) ($body[$body['mode']] ?? []), 'is_array'), 'key'),
                'graphql' => ['query', 'variables'],
                default => [],
            };
            $headers = array_column(array_filter((array) ($request['header'] ?? []), 'is_array'), 'key');
            $secured = (isset($request['auth']) ? self::authed($request['auth']) : $inherited) || self::credentialed($headers);
            $this->request('postman', (string) ($request['method'] ?? 'GET'), $url, $query, $fields, $secured);
        }

        return 'postman';
    }

    private function har(array $entries): string
    {
        foreach ($entries as $entry) {
            $request = is_array($entry) ? ($entry['request'] ?? null) : null;
            if (! is_array($request) || ! is_string($request['url'] ?? null) || strtoupper((string) ($request['method'] ?? '')) === 'OPTIONS') {
                continue;
            }
            $post = (array) ($request['postData'] ?? []);
            $fields = array_column(array_filter((array) ($post['params'] ?? []), 'is_array'), 'name')
                ?: self::textFields((string) ($post['text'] ?? ''), (string) ($post['mimeType'] ?? ''));
            $headers = array_column(array_filter((array) ($request['headers'] ?? []), 'is_array'), 'name');
            $query = array_column(array_filter((array) ($request['queryString'] ?? []), 'is_array'), 'name');
            $secured = self::credentialed($headers) || ! empty($request['cookies']);
            $this->request('har', (string) ($request['method'] ?? 'GET'), $request['url'], $query, $fields, $secured);
        }

        return 'har';
    }

    private function request(string $source, string $method, string $url, array $query, array $body, bool $auth): void
    {
        $host = null;
        if (preg_match('~^\{\{[^{}]*\}\}~', $url, $match)) {
            $url = substr($url, strlen($match[0]));
            $this->tally['hostless']++;
        } elseif (! str_starts_with($url, '/')) {
            $parts = parse_url(preg_match('~^[a-z][a-z0-9+.-]*:~i', $url) ? $url : 'https://'.$url);
            if (! is_array($parts) || ! in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true) || empty($parts['host'])) {
                return;
            }
            $host = strtolower($parts['host']);
            $url = ($parts['path'] ?? '/').'?'.($parts['query'] ?? '');
        }
        if ($host !== null && $this->hosts !== [] && ! in_array($host, $this->hosts, true)) {
            $this->skipped[$host] = true;

            return;
        }
        [$path, $queryString] = array_pad(explode('?', preg_split('~#~', $url, 2)[0], 2), 2, '');
        if (! preg_match(self::ASSET, $path)) {
            $host = $host === ($this->hosts[0] ?? null) || $this->hosts === [] ? null : $host;
            $this->add($method, $path, $host, [...self::queryNames($queryString), ...$query], $body, $auth, $source);
        }
    }

    private function add(string $method, string $path, ?string $host, array $params, array $body, bool $auth, string $source): void
    {
        $method = strtoupper(trim($method));
        $normalized = self::path($path);
        $stored = in_array($source, ['har', 'postman'], true) ? self::path($path, true) : $normalized;
        $key = $method.' '.$host.$normalized;
        $valid = in_array($method, self::METHODS, true) && $normalized !== null && $stored !== null;
        if (! $valid || (! isset($this->endpoints[$key]) && count($this->endpoints) >= self::MAX_ENDPOINTS)) {
            $this->tally[$valid ? 'dropped' : 'invalid']++;

            return;
        }
        $template = str_contains($stored, '{');
        $entry = $this->endpoints[$key] ?? ['method' => $method, 'path' => $stored, 'host' => $host, 'params' => [], 'body' => [], 'auth' => false, 'source' => $source, 'template' => $template];
        if ($entry['template'] && ! $template) {
            [$entry['path'], $entry['template']] = [$stored, false];
        }
        $entry['params'] = self::names([...$entry['params'], ...$params]);
        $entry['body'] = self::names([...$entry['body'], ...$body]);
        $entry['auth'] = $entry['auth'] || $auth;
        $this->endpoints[$key] = $entry;
    }

    private function base(array $servers): array
    {
        $known = array_values(array_filter($servers, fn ($server) => $server[0] === null || $this->hosts === [] || in_array($server[0], $this->hosts, true)));
        if ($known === [] && $servers !== []) {
            $this->warnings[] = 'Servidores do documento fora das origens do ambiente ('.implode(', ', array_unique(array_column($servers, 0))).'): as rotas foram associadas à origem principal.';
        }
        [$host, $path] = $known[0] ?? [null, $servers[0][1] ?? ''];

        return [$host !== ($this->hosts[0] ?? null) && in_array($host, $this->hosts, true) ? $host : null, $path];
    }

    private function deref(mixed $node, int $depth = 0): mixed
    {
        if (! is_array($node) || ! is_string($node['$ref'] ?? null)) {
            return $node;
        }
        $target = $depth > 8 || ! str_starts_with($node['$ref'], '#/') ? null : $this->doc;
        foreach ($target === null ? [] : explode('/', substr($node['$ref'], 2)) as $segment) {
            $target = is_array($target) ? ($target[strtr(rawurldecode($segment), ['~1' => '/', '~0' => '~'])] ?? null) : null;
        }

        return $target === null ? [] : $this->deref($target, $depth + 1);
    }

    private function fields(mixed $schema, array $seen = []): array
    {
        if (++$this->nodes > self::MAX_NODES) {
            $this->tally['truncated']++;

            return [];
        }
        $ref = is_array($schema) && is_string($schema['$ref'] ?? null) ? $schema['$ref'] : null;
        if ($ref !== null && (isset($seen[$ref]) || isset($this->memo[$ref]))) {
            return $this->memo[$ref] ?? [];
        }
        $schema = $this->deref($schema);
        $seen += $ref === null ? [] : [$ref => true];
        $names = is_array($schema['properties'] ?? null) ? array_map('strval', array_keys($schema['properties'])) : [];
        foreach (['allOf', 'oneOf', 'anyOf'] as $combinator) {
            foreach (is_array($schema) ? (array) ($schema[$combinator] ?? []) : [] as $part) {
                $names = [...$names, ...$this->fields($part, $seen)];
            }
        }
        $names = array_values(array_unique($names));
        if ($ref !== null) {
            $this->memo[$ref] = $names;
        }

        return $names;
    }

    private function named(array $parameters, string $in): array
    {
        return array_column(array_filter($parameters, fn ($parameter) => ($parameter['in'] ?? null) === $in), 'name');
    }

    private function variable(string $name): ?string
    {
        foreach (array_filter((array) ($this->doc['variable'] ?? []), 'is_array') as $variable) {
            if (($variable['key'] ?? null) === $name && is_string($variable['value'] ?? null) && preg_match('~^https?://[^/?#\s]+(/[^?#\s]*)?$~i', $variable['value'])) {
                return rtrim($variable['value'], '/');
            }
        }

        return null;
    }

    private static function authed(mixed $auth): bool
    {
        return is_array($auth) && ! in_array($auth['type'] ?? 'noauth', ['noauth', 'inherit'], true);
    }

    private static function credentialed(array $headers): bool
    {
        return array_intersect(array_map(fn ($header) => strtolower(trim((string) $header)), $headers), ['authorization', 'cookie']) !== [];
    }

    private static function textFields(string $text, string $type): array
    {
        $json = $text === '' || strlen($text) > 524288 ? null : json_decode($text, true);
        if (is_array($json) && ! array_is_list($json)) {
            return array_map('strval', array_keys($json));
        }

        return str_contains(strtolower($type), 'urlencoded') && strlen($text) <= 524288 ? self::queryNames($text) : [];
    }

    private static function queryNames(string $query): array
    {
        return array_map(fn ($pair) => urldecode(explode('=', $pair, 2)[0]), array_filter(explode('&', $query), fn ($pair) => $pair !== ''));
    }

    private static function names(array $names): array
    {
        $names = array_filter(array_map(fn ($name) => is_scalar($name) ? trim((string) $name) : '', $names),
            fn ($name) => $name !== '' && strlen($name) <= 100 && mb_check_encoding($name, 'UTF-8') && ! preg_match('~[\x00-\x1F\x7F]~', $name));

        return array_slice(array_values(array_unique($names)), 0, 60);
    }
}
