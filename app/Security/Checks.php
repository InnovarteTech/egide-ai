<?php

namespace App\Security;

final class Checks
{
    public const SEVERITY = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];

    public const CVSS = [
        'critical' => ['score' => 9.8, 'rating' => 'Crítico'],
        'high' => ['score' => 7.5, 'rating' => 'Alto'],
        'medium' => ['score' => 5.3, 'rating' => 'Médio'],
        'low' => ['score' => 3.1, 'rating' => 'Baixo'],
    ];

    public static function cvss(string $severity): array
    {
        return self::CVSS[$severity] ?? ['score' => 0.0, 'rating' => 'Informativo'];
    }

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

        return ['verdict' => 'protegido', 'finding' => null];
    }

    public const FILES = [
        '.env' => [
            'signatures' => ['APP_KEY=', 'DB_PASSWORD=', 'SECRET_KEY=', 'AWS_SECRET_ACCESS_KEY=', 'DATABASE_URL='],
            'severity' => 'critical', 'title' => 'Arquivo .env exposto publicamente', 'reference' => 'OWASP A05:2021 · CWE-538',
            'remediation' => 'Remova o arquivo do diretório público, troque todas as credenciais que ele contém e bloqueie arquivos iniciados por ponto no servidor web.',
        ],
        '.git/HEAD' => [
            'signatures' => ['ref: refs/'],
            'severity' => 'high', 'title' => 'Repositório Git exposto', 'reference' => 'OWASP A05:2021 · CWE-527',
            'remediation' => 'Bloqueie o acesso a /.git no servidor web e remova a pasta do diretório publicado. O histórico pode conter código-fonte e segredos.',
        ],
        '.git/config' => [
            'signatures' => ['[core]'],
            'severity' => 'high', 'title' => 'Configuração do repositório Git exposta', 'reference' => 'OWASP A05:2021 · CWE-527',
            'remediation' => 'Bloqueie o acesso a /.git no servidor web e remova a pasta do diretório publicado.',
        ],
        'backup.sql' => [
            'signatures' => ['CREATE TABLE', 'INSERT INTO'], 'min' => 2,
            'severity' => 'critical', 'title' => 'Backup de banco de dados exposto', 'reference' => 'OWASP A05:2021 · CWE-530',
            'remediation' => 'Retire o backup do diretório público, guarde backups fora do servidor web e avalie quais dados foram expostos.',
        ],
        'dump.sql' => [
            'signatures' => ['CREATE TABLE', 'INSERT INTO'], 'min' => 2,
            'severity' => 'critical', 'title' => 'Backup de banco de dados exposto', 'reference' => 'OWASP A05:2021 · CWE-530',
            'remediation' => 'Retire o backup do diretório público, guarde backups fora do servidor web e avalie quais dados foram expostos.',
        ],
        'phpinfo.php' => [
            'signatures' => ['PHP Version', 'phpinfo()'], 'min' => 2, 'html' => true,
            'severity' => 'medium', 'title' => 'Página phpinfo exposta', 'reference' => 'OWASP A05:2021 · CWE-497',
            'remediation' => 'Remova o arquivo de diagnóstico do ambiente publicado.',
        ],
        'server-status' => [
            'signatures' => ['Apache Server Status'], 'html' => true,
            'severity' => 'medium', 'title' => 'Status do servidor Apache exposto', 'reference' => 'OWASP A05:2021 · CWE-497',
            'remediation' => 'Restrinja o mod_status a endereços internos.',
        ],
        'actuator/env' => [
            'signatures' => ['"propertySources"', '"activeProfiles"'],
            'severity' => 'high', 'title' => 'Endpoint Spring Actuator exposto', 'reference' => 'OWASP A05:2021 · CWE-497',
            'remediation' => 'Desative os endpoints sensíveis do Actuator ou proteja-os com autenticação.',
        ],
        '.DS_Store' => [
            'signatures' => ['Bud1'],
            'severity' => 'low', 'title' => 'Arquivo .DS_Store exposto', 'reference' => 'OWASP A05:2021 · CWE-538',
            'remediation' => 'Remova arquivos .DS_Store do diretório publicado. Eles revelam nomes de arquivos e pastas.',
        ],
    ];

    public const HEADERS = [
        'hsts' => [
            'severity' => 'medium', 'title' => 'HSTS ausente nas respostas HTTPS', 'reference' => 'OWASP A02:2021 · CWE-319',
            'detail' => 'O cabeçalho Strict-Transport-Security não foi enviado.',
            'remediation' => 'Envie Strict-Transport-Security: max-age=31536000; includeSubDomains em todas as respostas HTTPS.',
        ],
        'clickjacking' => [
            'severity' => 'medium', 'title' => 'Páginas podem ser embutidas em outro site', 'reference' => 'OWASP A05:2021 · CWE-1021',
            'detail' => 'Sem X-Frame-Options nem frame-ancestors na CSP, a página pode ser carregada em iframe para clickjacking.',
            'remediation' => 'Envie X-Frame-Options: DENY ou frame-ancestors \'none\' na Content-Security-Policy.',
        ],
        'csp' => [
            'severity' => 'low', 'title' => 'Content-Security-Policy ausente', 'reference' => 'OWASP A05:2021 · CWE-693',
            'detail' => 'As páginas HTML não definem uma política de conteúdo, o que amplia o impacto de um XSS.',
            'remediation' => 'Defina uma Content-Security-Policy restritiva, começando por default-src \'self\'.',
        ],
        'nosniff' => [
            'severity' => 'low', 'title' => 'X-Content-Type-Options ausente', 'reference' => 'OWASP A05:2021 · CWE-693',
            'detail' => 'O navegador pode reinterpretar o tipo do conteúdo.',
            'remediation' => 'Envie X-Content-Type-Options: nosniff.',
        ],
        'version' => [
            'severity' => 'low', 'title' => 'Servidor revela a versão do software', 'reference' => 'OWASP A05:2021 · CWE-497',
            'detail' => 'Os cabeçalhos expõem nome e versão da tecnologia, o que facilita buscar falhas conhecidas.',
            'remediation' => 'Remova a versão dos cabeçalhos Server e X-Powered-By.',
        ],
    ];

    public static function confirmed(array $check, array $probe): bool
    {
        return ($probe['status'] ?? 0) === 200 && empty($probe['blocked'])
            && count($probe['matches'] ?? []) >= ($check['min'] ?? 1)
            && (($check['html'] ?? false) || ! str_contains(strtolower($probe['type'] ?? ''), 'text/html'));
    }

    public static function isProbe(string $path): bool
    {
        foreach (array_keys(self::FILES) as $file) {
            if ($path === '/'.$file || str_ends_with($path, '/'.$file)) {
                return true;
            }
        }

        return false;
    }

    public static function normalizePath(string $path): string
    {
        return implode('/', array_map(
            fn ($segment) => preg_match('~^(?:\d+|[0-9a-fA-F-]{16,}|[A-Za-z0-9_-]{24,})$~D', $segment) ? ':id' : $segment,
            explode('/', $path),
        ));
    }

    public static function bases(array $scope): array
    {
        $path = parse_url($scope['url'], PHP_URL_PATH) ?: '/';
        $bases = ['/', rtrim($path, '/') ?: '/'];
        if (! str_ends_with($path, '/')) {
            $bases[] = rtrim(dirname($path), '/') ?: '/';
        }

        return array_values(array_unique($bases));
    }

    public static function headerFindings(array $issues): array
    {
        $findings = [];
        foreach ($issues as $issue => $paths) {
            $samples = array_slice(array_keys($paths), 0, 5);
            [$code, $value, $flags] = array_pad(explode(':', $issue, 3), 3, null);
            if ($code === 'cookie' && $value) {
                $missing = array_filter(explode(',', (string) $flags));
                $severity = array_intersect($missing, ['secure', 'httponly']) ? 'medium' : 'low';
                $findings[] = [
                    'title' => "Cookie {$value} sem atributos de proteção", 'severity' => $severity,
                    'category' => 'Configuração · cookies',
                    'evidence' => [
                        'kind' => 'config', 'method' => 'GET', 'path' => $samples[0], 'paths' => $samples,
                        'detail' => 'Atributos ausentes no Set-Cookie: '.implode(', ', array_map('ucfirst', $missing)).'.',
                        'reference' => 'OWASP A05:2021 · '.(in_array('secure', $missing, true) ? 'CWE-614' : (in_array('httponly', $missing, true) ? 'CWE-1004' : 'CWE-1275')),
                    ],
                    'remediation' => 'Emita o cookie com Secure, HttpOnly e SameSite=Lax ou Strict.',
                ];

                continue;
            }
            if (! isset(self::HEADERS[$code])) {
                continue;
            }
            $check = self::HEADERS[$code];
            $key = $code === 'version' ? 'version' : $issue;
            $detail = $check['detail'].($value ? ' Valor observado: '.$value.'.' : '');
            if (isset($findings[$key])) {
                $findings[$key]['evidence']['detail'] .= ' Valor observado: '.$value.'.';

                continue;
            }
            $findings[$key] = [
                'title' => $check['title'], 'severity' => $check['severity'],
                'category' => 'Configuração · cabeçalhos HTTP',
                'evidence' => [
                    'kind' => 'config', 'method' => 'GET', 'path' => $samples[0], 'paths' => $samples,
                    'detail' => $detail.' Observado em '.count($paths).' resposta'.(count($paths) === 1 ? '' : 's').'.',
                    'reference' => $check['reference'],
                ],
                'remediation' => $check['remediation'],
            ];
        }

        return array_values($findings);
    }
}
