<?php

namespace App\Security;

use App\Models\Scan;

class Hunter
{
    public const TECHNIQUES = ['xss', 'sqli_error', 'sqli_time', 'sqli_bool', 'nosql', 'traversal', 'ssrf', 'open_redirect', 'ssti', 'command', 'command_time', 'graphql'];

    private const NEEDS = ['xss' => ['{MARKER}'], 'ssti' => ['{A}', '{B}'], 'command' => ['{A}', '{B}'], 'ssrf' => ['{CALLBACK}'], 'open_redirect' => ['{CANARY}']];

    private const DESTRUCTIVE_SQL = '~\b(drop|delete|update|insert|truncate|alter|create|grant|revoke|merge|rename|replace\s+into|exec(ute)?|xp_\w+|sp_\w+|shutdown|into\s+(out|dump)file|load_file|pg_read_file|lo_import|copy\s+\w+\s+(from|to))\b~i';

    private const DESTRUCTIVE_NOSQL = '~\b(drop\w*|remove|delete\w*|update\w*|insert\w*|replace\w*|mapreduce|eval)\b~i';

    private const DESTRUCTIVE_SHELL = '~\b(rm|mv|cp|dd|mkfs|shred|truncate|shutdown|reboot|halt|poweroff|kill|pkill|killall|chmod|chown|chattr|curl|wget|nc|ncat|netcat|telnet|ssh|scp|ftp|tftp|bash|sh|zsh|python\d?|perl|ruby|php|node|powershell|pwsh|certutil|bitsadmin|crontab|useradd|passwd|sudo|su|mount|iptables|tee)\b|>~i';

    private const DESTRUCTIVE_TEMPLATE = '~(__globals__|__subclasses__|__class__|__mro__|__bases__|__init__|__builtins__|__import__|\bpopen\b|\bsystem\b|subprocess|commands\.|\beval\b|\bexec\b|getRuntime|Runtime\b|ProcessBuilder|\.exec\(|freemarker|javax\.script|getClass\(|forName|loadClass|@java|T\(java)~i';

    public function __construct(private ?Planner $planner = null) {}

    public function next(Scan $scan, array $context): array
    {
        return $this->planner->structured($scan, self::instruction(), $context, self::schema());
    }

    public static function schema(): array
    {
        return [
            'type' => 'object', 'additionalProperties' => false,
            'properties' => [
                'done' => ['type' => 'boolean'],
                'reason' => ['type' => 'string'],
                'experiment' => [
                    'type' => 'object', 'additionalProperties' => false,
                    'properties' => [
                        'method' => ['type' => 'string', 'enum' => ['GET', 'POST']],
                        'path' => ['type' => 'string'],
                        'point' => ['type' => 'string', 'enum' => ['query', 'body', 'path']],
                        'key' => ['type' => ['string', 'null']],
                        'technique' => ['type' => 'string', 'enum' => self::TECHNIQUES],
                        'payload' => ['type' => 'string'],
                        'false_payload' => ['type' => ['string', 'null']],
                        'rationale' => ['type' => 'string'],
                    ],
                    'required' => ['method', 'path', 'point', 'key', 'technique', 'payload', 'false_payload', 'rationale'],
                ],
            ],
            'required' => ['done', 'reason', 'experiment'],
        ];
    }

    public static function instruction(): string
    {
        return implode("\n", [
            'You are an autonomous, creative penetration tester working inside an AUTHORIZED test environment. Hunt for real, provable vulnerabilities in the listed endpoints.',
            'Every turn: study the inventory, the coverage already done, the proven findings and your previous experiments (status, size, response snippet, oracle verdict). Then propose ONE new experiment that has a real chance of succeeding. Never repeat an identical experiment; adapt to what the responses reveal.',
            'Think like an attacker: infer the backend from errors and headers, find the injection context from the snippet (HTML body, attribute, JS string, JSON, SQL, template, shell), and craft a payload for that exact context.',
            'You may use parameters that were not observed: hidden or debug parameters (debug, admin, test, preview, format, lang, template, view, file, path, page, include, cmd, exec, host, ip, callback, redirect, next, url, query, filter, sort, order, fields). Try JSON bodies, parameter pollution and case/encoding variants.',
            'Filter and WAF bypass: when the payload is escaped, stripped or blocked (403/406), change context and encoding: attribute breakout without angle brackets, event handlers, SVG/MathML, case mixing, HTML entities, URL and double URL encoding, Unicode escapes, comments inside keywords, polyglots.',
            'Techniques and the proof each oracle needs (placeholders are mandatory, the platform fills them in):',
            '- xss: put {MARKER} where it becomes live markup or script. Proof: the payload comes back raw in an HTML response.',
            '- sqli_error: make the database raise an error (quotes, parentheses, type casts, CAST/CONVERT, extractvalue). Proof: a database error signature.',
            '- sqli_time: delay at least 5 s (SLEEP, pg_sleep, WAITFOR DELAY, heavy randomblob). Proof: measured delay.',
            '- sqli_bool: payload = TRUE condition, false_payload = FALSE condition, both the same length. Proof: true matches the original, false changes it, twice.',
            '- nosql: operator injection ($ne, $gt, $regex, $where) in query or JSON body. Proof: a document-database error.',
            '- traversal: ../ sequences and encodings (%2e%2e%2f, ..%252f, ....//, absolute paths) towards /etc/passwd or windows/win.ini. Proof: the file signature.',
            '- ssti: evaluate {A}*{B} in a template syntax ({{...}}, ${...}, #{...}, <%= %>, [[...]], *{...}). Proof: the product appears.',
            '- command: shell metacharacters (; | && || backticks $()) running echo $(({A}*{B})). Proof: the product appears.',
            '- command_time: shell metacharacters running sleep 5 or ping -c 6 127.0.0.1. Proof: measured delay.',
            '- ssrf: give {CALLBACK} to anything that fetches a URL (url, webhook, image, feed, import, callback). Proof: the server calls our collector.',
            '- open_redirect: send {CANARY} as a host (//{CANARY}, https://{CANARY}, /\\{CANARY}). Proof: a 3xx Location to that host.',
            '- graphql: introspection query on GraphQL endpoints. Proof: the schema comes back.',
            'Non-negotiable rules: use only the listed paths and hosts; never destructive (no DROP, DELETE, UPDATE, INSERT, file writes, rm, kill, curl, wget or any external host); query and path points use GET, body points use POST; include the placeholder the chosen oracle needs.',
            'When the surface is exhausted, set done=true and explain why in reason. Otherwise done=false. Write rationale and reason in short Portuguese.',
        ]);
    }

    public static function guard(array $experiment, callable $inScope): ?string
    {
        $technique = $experiment['technique'] ?? null;
        $payload = (string) ($experiment['payload'] ?? '');
        $false = (string) ($experiment['false_payload'] ?? '');
        $point = $experiment['point'] ?? null;
        $path = (string) ($experiment['path'] ?? '');
        if (! in_array($technique, self::TECHNIQUES, true)) {
            return 'técnica desconhecida';
        }
        if (! in_array($point, ['query', 'body', 'path'], true) || ($experiment['method'] ?? '') !== ($point === 'body' ? 'POST' : 'GET')) {
            return 'ponto e método incompatíveis';
        }
        if ($path === '' || ! $inScope($path)) {
            return 'rota fora do escopo autorizado';
        }
        if ($payload === '' || strlen($payload) > 300 || strlen($false) > 300) {
            return 'carga vazia ou longa demais';
        }
        foreach (self::NEEDS[$technique] ?? [] as $placeholder) {
            if (! str_contains($payload, $placeholder)) {
                return 'falta o marcador '.$placeholder.' que o oráculo usa como prova';
            }
        }
        if ($technique === 'sqli_bool' && $false === '') {
            return 'falta a condição falsa';
        }
        $text = str_replace('\\', '/', strtr($payload.' '.$false, ['{MARKER}' => '', '{A}' => '', '{B}' => '', '{CALLBACK}' => '', '{CANARY}' => '']));
        if (preg_match('~https?:/~i', $text) || preg_match('~//[a-z0-9.\-]*\.[a-z0-9\-]+~i', $text)) {
            return 'contato com host de terceiros';
        }
        $rules = match (true) {
            str_starts_with($technique, 'sqli') => [self::DESTRUCTIVE_SQL],
            $technique === 'nosql' => [self::DESTRUCTIVE_NOSQL],
            str_starts_with($technique, 'command') => [self::DESTRUCTIVE_SHELL],
            $technique === 'ssti' => [self::DESTRUCTIVE_SHELL, self::DESTRUCTIVE_TEMPLATE],
            default => [],
        };
        foreach ($rules as $rule) {
            if (preg_match($rule, $text)) {
                return 'operação destrutiva bloqueada';
            }
        }

        return null;
    }

    public static function resolve(array $experiment): array
    {
        $a = random_int(1009, 9973);
        $b = random_int(1009, 9973);
        $marker = Payloads::marker('egideXSS');
        $canary = Payloads::marker('egide-').'.invalid';
        $map = ['{MARKER}' => $marker, '{A}' => (string) $a, '{B}' => (string) $b, '{CALLBACK}' => Payloads::CALLBACK, '{CANARY}' => $canary];

        return [
            ...$experiment,
            'value' => strtr((string) $experiment['payload'], $map),
            'false' => strtr((string) ($experiment['false_payload'] ?? ''), $map),
            'marker' => $experiment['technique'] === 'open_redirect' ? $canary : $marker,
            'expected' => (string) ($a * $b),
        ];
    }
}
