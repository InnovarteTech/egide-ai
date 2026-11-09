<?php

namespace App\Security;

use App\Models\Target;
use Illuminate\Validation\ValidationException;

final class Scope
{
    public const LOCAL_SUFFIX = '.local.egide.test';

    public const RESERVED_PORTS = [22, 25, 53, 3306, 5432, 6379, 6387, 8791, 8792, 8899, 9200, 11211, 27017];

    public static function localEnabled(): bool
    {
        return app()->environment('local') && (bool) config('egide.local_targets');
    }

    public static function isLocalOrigin(string $origin): bool
    {
        return str_ends_with((string) parse_url($origin, PHP_URL_HOST), self::LOCAL_SUFFIX);
    }

    public static function origin(string $url): string
    {
        $parts = parse_url(trim($url));
        $host = strtolower($parts['host'] ?? '');

        if (($parts['scheme'] ?? null) !== 'https' || ! filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
            || ! str_contains($host, '.') || filter_var($host, FILTER_VALIDATE_IP)
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['port'])
            || isset($parts['query']) || isset($parts['fragment'])
            || ! in_array($parts['path'] ?? '', ['', '/'], true)) {
            throw ValidationException::withMessages(['origin' => 'Informe a origem HTTPS, como https://staging.empresa.com.br.']);
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
            if (! preg_match('~^(GET|HEAD|POST)\s+(\S+)$~D', trim($line), $matches)) {
                throw ValidationException::withMessages(['rules' => 'Use uma regra por linha, como GET /faturas/* ou POST /login.']);
            }

            $prefix = str_ends_with($matches[2], '/*');
            $path = $prefix ? (substr($matches[2], 0, -2) ?: '/') : $matches[2];
            if (! self::path($path) || ($prefix && $matches[1] === 'POST')) {
                throw ValidationException::withMessages(['rules' => 'Use rotas exatas para POST. Informe os caminhos sem parâmetros.']);
            }
            $rules[] = ['method' => $matches[1], 'path' => $path, 'prefix' => $prefix];
        }

        return $rules;
    }

    public static function allows(array $scope, string $method, string $path): bool
    {
        if (! self::path($path)) {
            return false;
        }

        foreach ($scope['denied'] as $denied) {
            if ($path === $denied || str_starts_with($path, $denied.'/')) {
                return false;
            }
        }

        foreach ($scope['rules'] as $rule) {
            if ($rule['method'] === $method && ($path === $rule['path'] || ($rule['prefix']
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

    public static function origins(Target $target): array
    {
        $origins = [$target->origin];
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

        return [
            'url' => ($urls['a'] ?? $target->origin.$target->entry_path), 'lab' => false,
            'urls' => $urls, 'rules' => $target->rules, 'denied' => $target->denied,
            'local_port' => $target->local_port ?: null,
        ];
    }

    public static function verify(Target $target): bool
    {
        if ($target->local_port) {
            return self::localEnabled() && ! array_filter(self::origins($target), fn ($origin) => ! self::isLocalOrigin($origin));
        }
        foreach (self::origins($target) as $origin) {
            if (! self::verifyOrigin($origin, $target->verification_token)) {
                return false;
            }
        }

        return true;
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
