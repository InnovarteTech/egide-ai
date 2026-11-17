<?php

namespace App\Security;

final class ApiOracles
{
    public const SENSITIVE_FIELDS = [
        'role', 'is_admin', 'isAdmin', 'admin', 'is_verified', 'isVerified', 'verified', 'email_verified',
        'is_active', 'active', 'status', 'owner_id', 'user_id', 'tenant_id', 'account_id', 'organization_id',
        'price', 'amount', 'total', 'balance', 'credit', 'discount', 'discount_percentage', 'plan', 'subscription',
        'permissions', 'scopes', 'approved',
    ];

    public static function massAssignmentAssess(string $path, string $field, string $sentinel, array $write, array $after): array
    {
        if (! empty($write['blocked']) || (int) ($write['status'] ?? 0) === 0 || (int) ($after['status'] ?? 0) !== 200) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        $value = null;
        foreach ($after['fields'] ?? [] as $pair) {
            if (($pair['key'] ?? null) === $field) {
                $value = $pair['value'] ?? null;
            }
        }
        if ($value === $sentinel) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Servidor aceita campo privilegiado fora do formulário', 'severity' => 'critical',
                'category' => 'Mass assignment · atribuição em massa',
                'evidence' => ['method' => 'PATCH', 'path' => $path, 'field' => $field, 'persisted' => true,
                    'write_status' => $write['status'] ?? null, 'reference' => 'OWASP API3:2023 · CWE-915'],
                'remediation' => 'Aceite no servidor apenas os campos previstos (allowlist); ignore campos como role, is_admin, tenant_id, owner_id ou price enviados pelo cliente.',
            ]];
        }

        return ['verdict' => 'protegido', 'finding' => null];
    }

    public static function prototypePollutionAssess(string $path, string $marker, string $controlSample): array
    {
        if ($marker === '') {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        if (str_contains($controlSample, $marker)) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Prototype pollution: propriedade injetada contaminou outros objetos', 'severity' => 'high',
                'category' => 'InjectionCheck · prototype pollution',
                'evidence' => ['method' => 'POST', 'path' => $path, 'reference' => 'CWE-1321',
                    'detail' => 'Uma propriedade injetada via __proto__/constructor reapareceu numa leitura subsequente, indício de poluição de protótipo / estado compartilhado. O conteúdo não foi armazenado.'],
                'remediation' => 'Rejeite chaves __proto__, constructor e prototype na entrada; use Object.create(null) ou Map para dados do cliente e congele o protótipo.',
            ]];
        }

        return ['verdict' => 'protegido', 'finding' => null];
    }

    public static function graphqlBatchingAssess(string $path, int $aliasesSent, int $aliasesExecuted): array
    {
        if ($aliasesSent < 2 || $aliasesExecuted <= 0) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        if ($aliasesExecuted >= 2) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'GraphQL executa operações em lote (alias) sem limite', 'severity' => 'medium',
                'category' => 'InventoryCheck · GraphQL batching',
                'evidence' => ['method' => 'POST', 'path' => $path, 'aliases' => $aliasesExecuted, 'reference' => 'OWASP API4:2023 · CWE-770',
                    'detail' => $aliasesExecuted.' operações rodaram numa única requisição. Isso multiplica qualquer ação (login, OTP, reset) e fura o rate-limit por requisição.'],
                'remediation' => 'Limite o número de aliases/operações por requisição e aplique custo de query; conte tentativas por operação, não por requisição.',
            ]];
        }

        return ['verdict' => 'protegido', 'finding' => null];
    }

    public static function unauthorizedWriteAssess(string $path, string $method, int $status): array
    {
        if (! in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        if (in_array($status, [200, 201, 202, 204], true)) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Escrita aceita sem autenticação ('.$method.')', 'severity' => 'high',
                'category' => 'AuthCheck · método de escrita sem sessão',
                'evidence' => ['method' => $method, 'path' => $path, 'status' => $status, 'reference' => 'OWASP API5:2023 · CWE-285',
                    'detail' => 'O servidor executou '.$method.' sem cookie nem token de sessão e respondeu '.$status.'. Qualquer um na internet altera o estado deste recurso.'],
                'remediation' => 'Exija autenticação e autorização em toda rota que altera estado; recuse métodos de escrita para requisições anônimas com 401/403.',
            ]];
        }
        if (in_array($status, [401, 403, 405], true)) {
            return ['verdict' => 'protegido', 'finding' => null];
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    public static function raceAssess(string $path, int $succeeded): array
    {
        if ($succeeded <= 0) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }
        if ($succeeded >= 2) {
            return ['verdict' => 'falha', 'finding' => [
                'title' => 'Race condition: ação de uso único executada em paralelo', 'severity' => 'high',
                'category' => 'LogicCheck · race condition (TOCTOU)',
                'evidence' => ['method' => 'POST', 'path' => $path, 'concurrent_ok' => $succeeded, 'reference' => 'CWE-362',
                    'detail' => $succeeded.' requisições paralelas idênticas foram aceitas numa operação que deveria valer uma vez só. Permite double-spend, cupom duplicado ou escalonamento.'],
                'remediation' => 'Serialize a operação com trava/transação atômica (SELECT ... FOR UPDATE, lock otimista ou chave idempotente) antes de aplicar o efeito.',
            ]];
        }

        return ['verdict' => 'protegido', 'finding' => null];
    }

    public static function xxeAssess(string $path, int $callbackHits): array
    {
        if ($callbackHits <= 0) {
            return ['verdict' => 'nao_testado', 'finding' => null];
        }

        return ['verdict' => 'falha', 'finding' => [
            'title' => 'XXE: parser XML resolve entidade externa', 'severity' => 'high',
            'category' => 'InjectionCheck · XXE (entidade externa)',
            'evidence' => ['method' => 'POST', 'path' => $path, 'callback_hits' => $callbackHits, 'reference' => 'OWASP A05:2021 · CWE-611',
                'detail' => 'Um XML com entidade externa SYSTEM fez o servidor chamar o coletor out-of-band da Égide. Um parser que resolve DTD/entidade externa permite ler arquivos locais e SSRF. O conteúdo não foi armazenado.'],
            'remediation' => 'Desabilite DTD e entidades externas no parser (libxml_disable_entity_loader / FEATURE_SECURE_PROCESSING / noent desligado); não resolva entidades em XML vindo do cliente.',
        ]];
    }

    public static function cloudMetadataAssess(string $path, string $sample): array
    {
        // Só assinaturas que aparecem na RESPOSTA real de metadados — nunca substrings presentes
        // na própria URL injetada (iam/security-credentials/, computeMetadata/v1), senão um alvo que
        // ecoa o parâmetro vira falso-positivo crítico.
        $patterns = [
            '~"SecretAccessKey"\s*:~',
            '~\bami-id\b.{0,400}\binstance-id\b~s',
            '~"access_token"\s*:.{0,80}"token_type"\s*:~s',
            '~"azEnvironment"~',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $sample)) {
                return ['verdict' => 'falha', 'finding' => [
                    'title' => 'SSRF expõe metadados da instância de nuvem', 'severity' => 'critical',
                    'category' => 'SSRF · metadados de nuvem',
                    'evidence' => ['method' => 'GET', 'path' => $path, 'reference' => 'OWASP A10:2021 · CWE-918',
                        'detail' => 'Uma injeção de SSRF alcançou o endpoint de metadados da nuvem (169.254.169.254 / metadata.google.internal) e a resposta trouxe credenciais/identidade da instância — permite roubo de credenciais temporárias e escalonamento na nuvem. O conteúdo não foi armazenado.'],
                    'remediation' => 'Bloqueie no servidor requisições a 169.254.169.254 e a redes internas; exija IMDSv2 com hop-limit 1; use allowlist de hosts para qualquer requisição feita pelo servidor.',
                ]];
            }
        }

        return ['verdict' => 'nao_testado', 'finding' => null];
    }

    public static function aliasFlood(string $field, string $args, int $count): string
    {
        $ops = [];
        for ($i = 0; $i < $count; $i++) {
            $ops[] = 'egideAlias'.$i.': '.$field.$args;
        }

        return '{'.implode(' ', $ops).'}';
    }
}
