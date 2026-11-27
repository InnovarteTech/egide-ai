<?php

namespace App\Security;

use App\Models\Target;
use Illuminate\Support\Facades\Http;
use Illuminate\Validation\ValidationException;

final class Scope
{
    public const LOCAL_SUFFIX = '.local.egide.test';

    public const RESERVED_PORTS = [22, 25, 53, 3306, 5432, 6379, 6387, 8791, 8792, 8899, 9200, 11211, 27017];

    public const SAFETY_MODES = ['canario', 'livre', 'mapeamento'];

    public static function localEnabled(): bool
    {
        return app()->environment('local') && (bool) config('egide.local_targets');
    }

    public static function isLocalOrigin(string $origin): bool
    {
        return str_ends_with((string) parse_url($origin, PHP_URL_HOST), self::LOCAL_SUFFIX);
    }

    public static function origin(string $url, string $field = 'origin'): string
    {
        $parts = parse_url(trim($url));
        $host = strtolower($parts['host'] ?? '');

        if (($parts['scheme'] ?? null) !== 'https' || ! filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
            || ! str_contains($host, '.') || filter_var($host, FILTER_VALIDATE_IP)
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['port'])
            || isset($parts['query']) || isset($parts['fragment'])
            || ! in_array($parts['path'] ?? '', ['', '/'], true)) {
            throw ValidationException::withMessages([$field => 'Informe a origem HTTPS, como https://staging.empresa.com.br.']);
        }

        return 'https://'.$host;
    }

    public static function path(string $path): bool
    {
        return preg_match('~^/(?:[a-zA-Z0-9._@-]+/)*[a-zA-Z0-9._@-]*$~D', $path) === 1
            && ! preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $path);
    }

    public static function rules(string $input): array
    {
        $rules = [];
        foreach (preg_split('/\R/', trim($input)) as $line) {
            if (! preg_match('~^(GET|HEAD|POST|PUT|PATCH|DELETE|\*)\s+(\S+)$~D', trim($line), $matches)) {
                throw ValidationException::withMessages(['rules' => 'Use uma regra por linha, como GET /faturas/*, POST /login ou * /* para liberar tudo.']);
            }

            $prefix = str_ends_with($matches[2], '/*');
            $path = $prefix ? (substr($matches[2], 0, -2) ?: '/') : $matches[2];
            if (! self::path($path) || ($prefix && ! in_array($matches[1], ['GET', 'HEAD', '*'], true))) {
                throw ValidationException::withMessages(['rules' => 'Prefixo /* só em GET, HEAD ou *. Para POST, PUT, PATCH e DELETE use rotas exatas, sem parâmetros.']);
            }
            $rules[] = ['method' => $matches[1], 'path' => $path, 'prefix' => $prefix];
        }

        return $rules;
    }

    public static function route(array $scope, string $route): ?array
    {
        if (! str_starts_with($route, 'https://')) {
            return self::path($route) ? ['host' => null, 'path' => $route] : null;
        }
        $parts = parse_url($route);
        $api = isset($scope['api']) ? parse_url($scope['api'], PHP_URL_HOST) : null;
        if (! $api || ($parts['host'] ?? null) !== $api || isset($parts['port']) || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment']) || ! self::path($parts['path'] ?? '')) {
            return null;
        }

        return ['host' => $api, 'path' => $parts['path']];
    }

    public static function budget(string $mode, ?string $environment, int $requested): int
    {
        $max = $mode === 'external' ? ($environment === 'test' ? 2000 : 180) : 600;

        return max(10, min($max, $requested));
    }

    public static function lab(string $variant): array
    {
        return [
            'url' => "http://lab.egide.test:8788/{$variant}", 'lab' => true,
            'rules' => [
                ['method' => 'GET', 'path' => "/{$variant}", 'prefix' => true],
                ['method' => 'GET', 'path' => "/servicos/{$variant}", 'prefix' => true],
                ['method' => 'GET', 'path' => '/favicon.ico', 'prefix' => false],
                ['method' => 'POST', 'path' => "/{$variant}/cadastro", 'prefix' => false],
                ['method' => 'POST', 'path' => "/{$variant}/entrar", 'prefix' => false],
                ['method' => 'POST', 'path' => "/servicos/{$variant}/graphql", 'prefix' => false],
                ['method' => 'POST', 'path' => "/servicos/{$variant}/importar", 'prefix' => false],
                ['method' => 'POST', 'path' => "/servicos/{$variant}/transferir", 'prefix' => false],
                ['method' => 'POST', 'path' => "/servicos/{$variant}/preferencias", 'prefix' => false],
                ['method' => 'POST', 'path' => "/servicos/{$variant}/resgatar", 'prefix' => false],
                ['method' => 'DELETE', 'path' => "/servicos/{$variant}/reservas", 'prefix' => true],
            ],
            'denied' => ['/administracao', '/pagamentos'],
            'write' => ['method' => 'PATCH', 'host' => 'lab.egide.test', 'path' => "/servicos/{$variant}/extratos", 'prefix' => true, 'max' => 4],
        ];
    }

    public static function allows(array $scope, string $method, string $path): bool
    {
        $route = self::route($scope, $path);
        if ($route === null) {
            return false;
        }
        $path = $route['path'];

        foreach ($scope['denied'] as $denied) {
            if ($path === $denied || str_starts_with($path, $denied.'/')) {
                return false;
            }
        }

        foreach ($scope['rules'] as $rule) {
            if (($rule['method'] === $method || $rule['method'] === '*') && ($path === $rule['path'] || ($rule['prefix']
                && ($rule['path'] === '/' || str_starts_with($path, $rule['path'].'/'))))) {
                return true;
            }
        }

        return false;
    }

    public static function sibling(string $origin, string $account): bool
    {
        $base = parse_url($origin, PHP_URL_HOST);
        $host = parse_url($account, PHP_URL_HOST);
        if (! is_string($base) || ! is_string($host)) {
            return false;
        }
        $parent = substr_count($base, '.') >= 2 ? substr($base, strpos($base, '.') + 1) : $base;
        if (preg_match('/^(?:com|net|org|gov|edu|co|ac|art|blog|eco|ind|inf|med|tec|app|dev)\.[a-z]{2}$/D', $parent)) {
            $parent = $base;
        }

        return $host === $base || str_ends_with($host, '.'.$parent);
    }

    public static function registrable(string $host): string
    {
        $host = strtolower(trim($host, '.'));
        $labels = explode('.', $host);
        if (count($labels) <= 2) {
            return $host;
        }
        $lastTwo = implode('.', array_slice($labels, -2));
        $take = preg_match('/^(?:com|net|org|gov|edu|co|ac|art|blog|eco|ind|inf|med|tec|app|dev)\.[a-z]{2}$/D', $lastTwo) ? 3 : 2;

        return implode('.', array_slice($labels, -$take));
    }

    public static function dnsDomains(Target $target): array
    {
        return array_values(array_unique(array_map(
            fn ($origin) => self::registrable((string) parse_url($origin, PHP_URL_HOST)),
            self::origins($target),
        )));
    }

    public static function origins(Target $target): array
    {
        $origins = array_filter([$target->origin, $target->api_origin]);
        foreach ((array) $target->credentials as $account) {
            if (! empty($account['origin'])) {
                $origins[] = $account['origin'];
            }
        }

        return array_values(array_unique($origins));
    }

    public static function launch(Target $target): array
    {
        $urls = [];
        $accounts = (array) $target->credentials;
        if (array_filter($accounts, fn ($account) => ! empty($account['origin']))) {
            foreach ($accounts as $actor => $account) {
                $urls[$actor] = ($account['origin'] ?? $target->origin).$target->entry_path;
            }
        }

        $write = null;
        $writePath = $accounts['a']['path'] ?? null;
        if ($target->write_test && is_string($writePath) && $target->environment_type !== 'production') {
            $parts = str_starts_with($writePath, 'https://')
                ? ['host' => parse_url($writePath, PHP_URL_HOST), 'path' => parse_url($writePath, PHP_URL_PATH)]
                : ['host' => parse_url($accounts['a']['origin'] ?? $target->origin, PHP_URL_HOST), 'path' => $writePath];
            $write = ['method' => 'PATCH', 'host' => $parts['host'], 'path' => $parts['path'], 'max' => 4];
        }

        $launchAccounts = [];
        foreach ($accounts as $actor => $account) {
            $launchAccounts[$actor] = [
                'role' => in_array($account['role'] ?? 'normal', ['admin', 'normal'], true) ? ($account['role'] ?? 'normal') : 'normal',
                'marker' => $account['marker'] ?? null, 'path' => $account['path'] ?? null,
                'origin' => $account['origin'] ?? null,
            ];
        }

        $focus = is_string($target->focus) ? mb_substr(trim($target->focus), 0, 500) : '';

        return [
            'url' => ($urls['a'] ?? $target->origin.$target->entry_path), 'lab' => false, 'api' => $target->api_origin ?: null,
            'urls' => $urls, 'rules' => $target->rules, 'denied' => $target->denied,
            'local_port' => $target->local_port ?: null, 'write' => $write, 'accounts' => $launchAccounts,
            'env_type' => $target->environment_type === 'test' ? 'test' : 'production',
            'safety' => $target->environment_type !== 'test' ? 'mapeamento'
                : (in_array($target->safety, self::SAFETY_MODES, true) ? $target->safety : 'canario'),
            'approved_writes' => array_values(array_filter(self::decoded($target->approved_writes), 'is_array')),
            'max_rps' => is_numeric($target->max_rps) && (float) $target->max_rps > 0 ? (float) $target->max_rps : null,
            'focus' => $focus !== '' ? $focus : null,
        ];
    }

    public static function decoded(mixed $value): array
    {
        $value = is_string($value) ? json_decode($value, true) : $value;

        return is_array($value) ? $value : [];
    }

    public static function verify(Target $target): bool
    {
        if ($target->local_port) {
            return self::localEnabled() && ! array_filter(self::origins($target), fn ($origin) => ! self::isLocalOrigin($origin));
        }
        $origins = self::origins($target);
        foreach ($origins as $origin) {
            if (! self::originVerified($origin, $target->verification_token)) {
                return false;
            }
        }

        return ! empty($origins);
    }

    private static function originVerified(string $origin, string $token): bool
    {
        $host = (string) parse_url($origin, PHP_URL_HOST);

        return self::dnsHasToken($host, $token)
            || self::dnsHasToken(self::registrable($host), $token)
            || self::verifyOrigin($origin, $token);
    }

    private static function dnsHasToken(string $label, string $token): bool
    {
        if (! preg_match('/^[a-z0-9.-]{1,240}$/D', $label)) {
            return false;
        }
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $records = @dns_get_record('_egide-verification.'.$label, DNS_TXT);
            if ($records === false) {
                usleep(300000);

                continue;
            }
            foreach ($records as $record) {
                if (hash_equals($token, trim((string) ($record['txt'] ?? '')))) {
                    return true;
                }
            }
            break;
        }

        // O resolver do servidor pode estar com cache velho/incompleto; confirma via DNS-over-HTTPS
        // em resolvers públicos, para a verificação não depender do resolver da máquina.
        return self::dohHasToken($label, $token);
    }

    private static function dohHasToken(string $label, string $token): bool
    {
        foreach (['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'] as $endpoint) {
            try {
                $response = Http::timeout(5)->withHeaders(['Accept' => 'application/dns-json'])
                    ->get($endpoint, ['name' => '_egide-verification.'.$label, 'type' => 'TXT']);
                if (! $response->successful()) {
                    continue;
                }
                foreach ((array) $response->json('Answer', []) as $answer) {
                    if (hash_equals($token, trim((string) ($answer['data'] ?? ''), " \t\n\r\0\x0B\""))) {
                        return true;
                    }
                }
            } catch (\Throwable) {
            }
        }

        return false;
    }

    private static function verifyOrigin(string $origin, string $token): bool
    {
        $host = parse_url($origin, PHP_URL_HOST);
        $addresses = gethostbynamel($host) ?: [];
        if (! $addresses || array_filter($addresses, fn ($ip) => ! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE))) {
            return false;
        }

        $body = '';
        $connection = curl_init($origin.'/.well-known/egide-verification.txt');
        curl_setopt_array($connection, [
            CURLOPT_PROXY => '',
            CURLOPT_RESOLVE => ["{$host}:443:{$addresses[0]}"],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_WRITEFUNCTION => function ($connection, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > 128) {
                    return 0;
                }
                $body .= $chunk;

                return strlen($chunk);
            },
        ]);
        try {
            return curl_exec($connection) === true
                && curl_getinfo($connection, CURLINFO_RESPONSE_CODE) === 200
                && hash_equals($token, trim($body));
        } finally {
            curl_close($connection);
        }
    }
}
