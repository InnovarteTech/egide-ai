<?php

namespace App\Security;

final class PayloadOracles
{
    public static function sqlErrorAssess(string $path, string $sample): array
    {
        $signatures = '~(SQLSTATE\[|mysqli?_|mysql_fetch|PG::\w|pg_query|psql:|ORA-\d{4,5}|SQLite3?::|SQLiteException|Unclosed quotation mark|quoted string not properly terminated|unterminated quoted|Microsoft OLE DB|ODBC SQL|near \"[^\"]*\": syntax error|SQL syntax|valid MySQL result|Warning.*\bpg_)~i';
        if (preg_match($signatures, $sample)) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Injeção de SQL por erro (mensagem do banco)', 'severity' => 'high',
                'category' => 'InjectionCheck · SQLi por erro',
                'evidence' => ['method' => 'GET', 'path' => $path, 'reference' => 'OWASP A03:2021 · CWE-89',
                    'detail' => 'A resposta vazou uma mensagem de erro do banco ao receber um metacaractere de SQL. O conteúdo não foi armazenado.'],
                'remediation' => 'Use consultas parametrizadas e desligue a exibição de erros do banco em produção.',
            ]];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    public static function traversalAssess(string $path, string $sample): array
    {
        if (preg_match('~root:.*?:0:0:~', $sample) || str_contains($sample, '; for 16-bit app support')) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Travessia de diretório expõe arquivo do sistema', 'severity' => 'high',
                'category' => 'InjectionCheck · path traversal',
                'evidence' => ['method' => 'GET', 'path' => $path, 'reference' => 'OWASP A01:2021 · CWE-22',
                    'detail' => 'A resposta devolveu a assinatura de um arquivo do sistema (passwd ou win.ini) a partir de uma carga de travessia. O conteúdo não foi armazenado.'],
                'remediation' => 'Normalize e valide caminhos no servidor; nunca concatene entrada do cliente em caminhos de arquivo e restrinja a um diretório base.',
            ]];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    public static function domXssAssess(string $token, array $probe): array
    {
        if (! empty($probe['executed']) && ($probe['token'] ?? null) === $token) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'XSS no DOM (execução de script confirmada no navegador)', 'severity' => 'high',
                'category' => 'InjectionCheck · DOM XSS',
                'evidence' => ['token' => $token, 'executed' => true, 'reference' => 'OWASP A03:2021 · CWE-79',
                    'detail' => 'A carga injetada via fonte client-side (hash/parâmetro) executou script no DOM — confirmado por marcador de execução no navegador.'],
                'remediation' => 'Nunca passe entrada do cliente a sinks perigosos (dangerouslySetInnerHTML, innerHTML, eval, href javascript:); use Trusted Types e sanitização no cliente.',
            ]];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    public static function noSqlAssess(string $path, string $sample): array
    {
        if (preg_match('~(MongoError|MongoServerError|BSONError|CastError to ObjectId|E11000 duplicate key|unknown top level operator|MongoParseError|CouchbaseException|RethinkDBError)~i', $sample)) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Injeção NoSQL (erro do banco de documentos)', 'severity' => 'high',
                'category' => 'InjectionCheck · NoSQL',
                'evidence' => ['method' => 'GET', 'path' => $path, 'reference' => 'OWASP A03:2021 · CWE-943',
                    'detail' => 'A resposta vazou um erro de banco NoSQL ao receber um operador de consulta. O conteúdo não foi armazenado.'],
                'remediation' => 'Valide tipos e rejeite operadores ($ne, $gt, $where) na entrada; use consultas parametrizadas do driver.',
            ]];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    public static function graphqlAssess(string $path, string $sample): array
    {
        $introspected = str_contains($sample, '"data"')
            && (str_contains($sample, '__schema') || str_contains($sample, 'queryType'))
            && ! str_contains($sample, '"errors"');
        if ($introspected) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Introspecção de GraphQL habilitada', 'severity' => 'medium',
                'category' => 'InventoryCheck · GraphQL introspection',
                'evidence' => ['method' => 'POST', 'path' => $path, 'reference' => 'OWASP API9:2023 · CWE-200',
                    'detail' => 'O endpoint respondeu à consulta de introspecção com o schema, expondo toda a superfície da API. O conteúdo não foi armazenado.'],
                'remediation' => 'Desligue a introspecção do GraphQL em produção e restrinja o schema a clientes autorizados.',
            ]];
        }

        return ['verdict' => str_contains($sample, '"errors"') || str_contains($sample, '"data"') ? 'protegido' : 'nao_testado', 'finding' => null];
    }

    public static function usable(array $response): bool
    {
        return ! empty($response['status']) && empty($response['blocked']) && ! in_array((int) $response['status'], [429, 503], true);
    }

    public static function booleanRound(string $payload, array $base, array $round): string
    {
        $responses = [...$base, ...$round];
        if (count($base) < 2 || count($round) < 2 || count(array_filter($responses, [self::class, 'usable'])) !== count($responses)) {
            return 'untestable';
        }
        [$first, $second] = $base;
        [$true, $false] = $round;
        if ($first['status'] !== $second['status']) {
            return 'untestable';
        }
        $body = fn (array $response) => (string) ($response['sample'] ?? '');
        $size = fn (array $response) => self::size($response);
        $whole = ! array_filter($responses, fn (array $response) => isset($response['size'])
            ? $response['size'] > self::utf16($body($response)) : self::utf16($body($response)) >= 2000);
        $same = fn (array $a, array $b) => $body($a) === $body($b) && $size($a) === $size($b);
        $stable = $same($first, $second);
        $noise = abs($size($first) - $size($second));
        $reflection = 6 * strlen($payload) + 16;
        $trueLikeBase = $true['status'] === $first['status'] && abs($size($true) - $size($first)) <= $noise + $reflection;
        $falseDiffers = $false['status'] !== $true['status']
            || ($stable && $whole && $same($true, $first) && ! $same($false, $true))
            || abs($size($false) - $size($true)) > $noise + 16;
        if ($trueLikeBase && $falseDiffers) {
            return 'holds';
        }

        return $stable && $whole ? 'fails' : 'untestable';
    }

    public static function booleanSqlAssess(string $path, string $payload, array $base, array $rounds, string $method = 'GET'): array
    {
        $untested = ['verdict' => 'nao_testado', 'finding' => null];
        if (! $rounds) {
            return $untested;
        }
        foreach ($rounds as $round) {
            $outcome = self::booleanRound($payload, $base, $round);
            if ($outcome !== 'holds') {
                return $outcome === 'fails' ? ['verdict' => 'protegido', 'finding' => null] : $untested;
            }
        }
        if (count($rounds) < 2) {
            return $untested;
        }
        [$true, $false] = $rounds[0];

        return ['verdict' => 'falha', 'finding' => [
            'title' => 'Injeção de SQL booleana (blind)', 'severity' => 'high',
            'category' => 'InjectionCheck · SQLi booleano',
            'evidence' => ['method' => $method, 'path' => $path, 'payload' => $payload, 'rounds' => count($rounds),
                'true_status' => $true['status'], 'false_status' => $false['status'],
                'length_delta' => abs(self::size($false) - self::size($true)), 'reference' => 'OWASP A03:2021 · CWE-89',
                'detail' => 'A condição verdadeira reproduziu a resposta original e a condição falsa mudou a resposta, de forma consistente em '.count($rounds).' rodadas. O conteúdo não foi armazenado.'],
            'remediation' => 'Use consultas parametrizadas (prepared statements); nunca concatene entrada do cliente em SQL.',
        ]];
    }

    private static function size(array $response): int
    {
        return (int) ($response['size'] ?? self::utf16((string) ($response['sample'] ?? '')));
    }

    private static function utf16(string $text): int
    {
        return intdiv(strlen(mb_convert_encoding($text, 'UTF-16LE', 'UTF-8')), 2);
    }

    public static function openRedirectAssess(string $path, string $host, array $network, string $method = 'GET', string $requestPath = ''): array
    {
        $target = strtolower($host);
        $sent = $requestPath !== '' ? $requestPath : $path;
        $probePath = parse_url($sent, PHP_URL_PATH) ?: $sent;
        $probeHost = parse_url($sent, PHP_URL_HOST);
        $answered = false;
        foreach ($network as $event) {
            if (empty($event['allowed'])) {
                continue;
            }
            $answered = $answered || (($event['path'] ?? null) === $probePath
                && (! is_string($probeHost) || strtolower((string) ($event['host'] ?? '')) === strtolower($probeHost)));
            $status = (int) ($event['status'] ?? 0);
            if ($status < 300 || $status >= 400 || self::redirectHost((string) ($event['location'] ?? '')) !== $target) {
                continue;
            }

            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Redirecionamento aberto para domínio externo', 'severity' => 'medium',
                'category' => 'RedirectCheck · open redirect',
                'evidence' => ['method' => $method, 'path' => $path, 'status' => $status, 'redirect_host' => $target,
                    'reference' => 'OWASP A01:2021 · CWE-601',
                    'detail' => 'O servidor respondeu com redirecionamento para um domínio controlado pelo teste a partir de um parâmetro da URL. O destino completo não foi armazenado.'],
                'remediation' => 'Aceite apenas caminhos relativos do próprio site ou uma lista fixa de destinos; rejeite URLs absolutas, "//" e "/\\" vindas do cliente.',
            ]];
        }

        return ['verdict' => $answered ? 'protegido' : 'nao_testado', 'finding' => null];
    }

    private static function redirectHost(string $location): ?string
    {
        $location = str_replace('\\', '/', preg_replace('~[\t\r\n]~', '', trim($location)));
        $location = preg_replace('~^(?:https?:)?/{2,}~i', 'https://', $location);
        $host = parse_url($location, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? rtrim(strtolower($host), '.') : null;
    }
}
