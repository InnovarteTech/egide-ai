<?php

namespace Tests\Unit;

use App\Security\AgenticRun;
use App\Security\SurfaceImport;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

class SurfaceImportTest extends TestCase
{
    private const ORIGINS = ['https://app.example.com', 'https://api.example.com'];

    private function openapi(array $overrides = []): array
    {
        return [
            'openapi' => '3.0.3', 'info' => ['title' => 'Loja', 'version' => '1'],
            'servers' => [['url' => 'https://api.example.com/v1']], 'security' => [['bearer' => []]],
            'paths' => [
                '/users/{userId}' => [
                    'parameters' => [['name' => 'userId', 'in' => 'path', 'required' => true]],
                    'get' => ['parameters' => [['name' => 'expand', 'in' => 'query'], ['$ref' => '#/components/parameters/Page'], ['name' => 'X-Trace', 'in' => 'header']]],
                    'put' => ['requestBody' => ['content' => ['application/json' => ['schema' => ['$ref' => '#/components/schemas/User']]]]],
                    'trace' => [],
                ],
                '/health' => ['get' => ['security' => []]],
                '/orders' => ['post' => ['requestBody' => ['$ref' => '#/components/requestBodies/Order']]],
            ],
            'components' => [
                'parameters' => ['Page' => ['name' => 'page', 'in' => 'query']],
                'schemas' => [
                    'User' => ['type' => 'object', 'properties' => ['name' => ['type' => 'string'], 'email' => ['example' => 'ana@example.com']]],
                    'Base' => ['properties' => ['note' => ['type' => 'string']]],
                ],
                'requestBodies' => ['Order' => ['content' => ['application/x-www-form-urlencoded' => ['schema' => [
                    'allOf' => [['$ref' => '#/components/schemas/Base'], ['properties' => ['sku' => [], 'qty' => []]]],
                ]]]]],
            ],
            ...$overrides,
        ];
    }

    private function table(array $result): array
    {
        $routes = [];
        foreach ($result['endpoints'] as $endpoint) {
            $key = $endpoint['method'].' '.($endpoint['host'] ? 'https://'.$endpoint['host'] : '').$endpoint['path'];
            $routes[$key] = [$endpoint['params'], $endpoint['body'], $endpoint['auth'], $endpoint['template']];
        }

        return $routes;
    }

    private function har(array $entries): string
    {
        return json_encode(['log' => ['version' => '1.2', 'entries' => array_map(fn ($request) => [
            'request' => ['headers' => [], 'queryString' => [], 'cookies' => [], ...$request], 'response' => ['content' => ['text' => 'resposta-sigilosa']],
        ], $entries)]]);
    }

    private function assertNoLeak(array $result, array $secrets): void
    {
        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, json_encode($result));
        }
    }

    public function test_openapi_3_is_normalized_with_server_base_path_refs_and_security(): void
    {
        $result = SurfaceImport::parse(json_encode($this->openapi()), 'openapi.json', self::ORIGINS);

        $this->assertSame(['format' => 'openapi', 'count' => 4, 'skipped_hosts' => [], 'warnings' => []], $result['meta']);
        $this->assertSame(['method' => 'GET', 'path' => '/v1/users/{id}', 'host' => 'api.example.com', 'params' => ['expand', 'page'], 'body' => [], 'auth' => true, 'source' => 'openapi', 'template' => true], $result['endpoints'][0]);
        $this->assertSame([
            'GET https://api.example.com/v1/users/{id}' => [['expand', 'page'], [], true, true],
            'PUT https://api.example.com/v1/users/{id}' => [[], ['name', 'email'], true, true],
            'GET https://api.example.com/v1/health' => [[], [], false, false],
            'POST https://api.example.com/v1/orders' => [[], ['note', 'sku', 'qty'], true, false],
        ], $this->table($result));
        $this->assertNoLeak($result, ['ana@example.com']);
    }

    public function test_openapi_servers_are_matched_against_the_target_origins(): void
    {
        $primary = SurfaceImport::parse(json_encode($this->openapi(['servers' => [['url' => 'https://app.example.com/api']]])), null, self::ORIGINS);
        $this->assertSame([null, '/api/users/{id}'], [$primary['endpoints'][0]['host'], $primary['endpoints'][0]['path']]);

        $spec = $this->openapi(['servers' => [['url' => 'https://{env}.prod.io/{version}', 'variables' => ['env' => ['default' => 'api'], 'version' => ['default' => 'v2']]]]]);
        $foreign = SurfaceImport::parse(json_encode($spec), null, self::ORIGINS);
        $this->assertSame([null, '/v2/users/{id}'], [$foreign['endpoints'][0]['host'], $foreign['endpoints'][0]['path']]);
        $this->assertSame([], $foreign['meta']['skipped_hosts']);
        $this->assertStringContainsString('api.prod.io', implode(' ', $foreign['meta']['warnings']));
    }

    public function test_openapi_yaml_is_accepted_when_the_parser_is_installed(): void
    {
        if (! class_exists(Yaml::class)) {
            $this->markTestSkipped('symfony/yaml indisponível.');
        }
        $yaml = "openapi: 3.1.0\ninfo: {title: Loja, version: '1'}\nservers:\n  - url: /api\npaths:\n  /pedidos/{id}:\n    delete:\n      security:\n        - cookie: []\n";

        $result = SurfaceImport::parse($yaml, 'openapi.yaml', self::ORIGINS);

        $this->assertSame('openapi', $result['meta']['format']);
        $this->assertSame(['method' => 'DELETE', 'path' => '/api/pedidos/{id}', 'host' => null, 'params' => [], 'body' => [], 'auth' => true, 'source' => 'openapi', 'template' => true], $result['endpoints'][0]);
    }

    public function test_swagger_2_uses_host_base_path_and_body_and_form_parameters(): void
    {
        $spec = [
            'swagger' => '2.0', 'host' => 'api.example.com', 'basePath' => '/api/',
            'paths' => [
                '/pets/{petId}' => ['get' => ['parameters' => [['name' => 'fields', 'in' => 'query'], ['name' => 'petId', 'in' => 'path']], 'security' => [['key' => []]]]],
                '/pets' => [
                    'post' => ['parameters' => [['name' => 'pet', 'in' => 'body', 'schema' => ['$ref' => '#/definitions/Pet']]]],
                    'put' => ['parameters' => [['name' => 'photo', 'in' => 'formData'], ['name' => 'caption', 'in' => 'formData']]],
                ],
            ],
            'definitions' => ['Pet' => ['properties' => ['name' => ['type' => 'string'], 'tag' => ['type' => 'string']]]],
        ];

        $result = SurfaceImport::parse(json_encode($spec), 'swagger.json', self::ORIGINS);

        $this->assertSame('swagger', $result['meta']['format']);
        $this->assertSame('swagger', $result['endpoints'][0]['source']);
        $this->assertSame([
            'GET https://api.example.com/api/pets/{id}' => [['fields'], [], true, true],
            'POST https://api.example.com/api/pets' => [[], ['name', 'tag'], false, false],
            'PUT https://api.example.com/api/pets' => [[], ['photo', 'caption'], false, false],
        ], $this->table($result));
    }

    public function test_postman_collection_walks_nested_folders_resolves_variables_and_drops_values(): void
    {
        $collection = [
            'info' => ['_postman_id' => 'abc', 'name' => 'Loja', 'schema' => 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'],
            'variable' => [['key' => 'baseUrl', 'value' => 'https://app.example.com'], ['key' => 'apiUrl', 'value' => 'https://api.example.com/v2/']],
            'item' => [
                ['name' => 'Usuários', 'auth' => ['type' => 'bearer', 'bearer' => [['key' => 'token', 'value' => 'segredo-do-bearer']]], 'item' => [
                    ['name' => 'Ver', 'request' => ['method' => 'get', 'url' => '{{baseUrl}}/api/users/:id?page=2&sort=nome']],
                    ['name' => 'Criar', 'request' => ['method' => 'POST', 'url' => '{{baseUrl}}/api/users',
                        'body' => ['mode' => 'raw', 'raw' => '{"name": "Ana", "password": "senha-super-secreta", "org": {{orgId}}}']]],
                    ['name' => 'Aninhado', 'item' => [['name' => 'Login', 'request' => [
                        'method' => 'POST', 'auth' => ['type' => 'noauth'],
                        'url' => ['raw' => 'https://api.example.com/auth/login', 'path' => ['auth', 'login'], 'query' => [['key' => 'next', 'value' => '/painel']]],
                        'body' => ['mode' => 'urlencoded', 'urlencoded' => [['key' => 'email', 'value' => 'a@example.com'], ['key' => 'senha', 'value' => 'x']]],
                    ]]]],
                ]],
                ['name' => 'Pedidos', 'request' => ['method' => 'GET', 'url' => '{{apiUrl}}/pedidos/2024?status=pago']],
                ['name' => 'Terceiro', 'request' => ['method' => 'GET', 'url' => 'https://evil.example.org/coleta']],
                ['name' => 'Sem host', 'request' => ['method' => 'DELETE', 'url' => '{{host}}/api/sessions/{{sessionId}}', 'header' => [['key' => 'Cookie', 'value' => 'sid=valor-do-cookie']]]],
                ['name' => 'Arquivo', 'request' => 'https://app.example.com/assets/app.js'],
            ],
        ];

        $result = SurfaceImport::parse(json_encode($collection), 'loja.postman_collection.json', self::ORIGINS);

        $this->assertSame('postman', $result['meta']['format']);
        $this->assertSame([
            'GET /api/users/{id}' => [['page', 'sort'], [], true, true],
            'POST /api/users' => [[], ['name', 'password', 'org'], true, false],
            'POST https://api.example.com/auth/login' => [['next'], ['email', 'senha'], false, false],
            'GET https://api.example.com/v2/pedidos/2024' => [['status'], [], false, false],
            'DELETE /api/sessions/{id}' => [[], [], true, true],
        ], $this->table($result));
        $this->assertSame(['evil.example.org'], $result['meta']['skipped_hosts']);
        $this->assertNoLeak($result, ['segredo-do-bearer', 'senha-super-secreta', 'valor-do-cookie', 'a@example.com', '/painel', 'Ana']);
    }

    public function test_har_filters_foreign_hosts_skips_assets_and_keeps_only_field_names(): void
    {
        $result = SurfaceImport::parse($this->har([
            ['method' => 'GET', 'url' => 'https://app.example.com/api/users/42?token=abc123&view=full', 'headers' => [['name' => 'Authorization', 'value' => 'Bearer jwt-sigiloso']]],
            ['method' => 'GET', 'url' => 'https://app.example.com/api/users/43?lang=pt#topo'],
            ['method' => 'POST', 'url' => 'https://api.example.com:443/api/login', 'postData' => ['mimeType' => 'application/json', 'text' => '{"email":"ana@example.com","password":"senha-har"}']],
            ['method' => 'POST', 'url' => 'https://app.example.com/api/forms', 'postData' => ['mimeType' => 'application/x-www-form-urlencoded', 'text' => 'campo=valor-form&outro.campo=2&%FF=x']],
            ['method' => 'PATCH', 'url' => 'https://app.example.com/api/docs/550e8400-e29b-41d4-a716-446655440000', 'cookies' => [['name' => 'sid', 'value' => 'cookie-har']]],
            ['method' => 'OPTIONS', 'url' => 'https://app.example.com/api/forms'],
            ['method' => 'GET', 'url' => 'https://app.example.com/api/convites/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.Xy3'],
            ['method' => 'GET', 'url' => 'https://app.example.com/api/contas/ana.silva@example.com/perfil'],
            ['method' => 'GET', 'url' => 'https://cdn.other.com/lib.js'],
            ['method' => 'GET', 'url' => 'https://tracker.other.com/collect'],
            ['method' => 'GET', 'url' => 'https://app.example.com/assets/app.css'],
            ['method' => 'GET', 'url' => 'data:image/png;base64,AAAA'],
        ]), 'sessao.har', self::ORIGINS);

        $this->assertSame('har', $result['meta']['format']);
        $this->assertSame([
            'GET /api/users/42' => [['token', 'view', 'lang'], [], true, false],
            'POST https://api.example.com/api/login' => [[], ['email', 'password'], false, false],
            'POST /api/forms' => [[], ['campo', 'outro.campo'], false, false],
            'PATCH /api/docs/550e8400-e29b-41d4-a716-446655440000' => [[], [], true, false],
            'GET /api/convites/{id}' => [[], [], false, true],
            'GET /api/contas/{id}/perfil' => [[], [], false, true],
        ], $this->table($result));
        $this->assertSame(['cdn.other.com', 'tracker.other.com'], $result['meta']['skipped_hosts']);
        $this->assertNoLeak($result, ['abc123', 'jwt-sigiloso', 'ana@example.com', 'senha-har', 'valor-form', 'cookie-har', 'resposta-sigilosa', 'eyJhbGciOiJIUzI1NiJ9', 'ana.silva@example.com']);
    }

    public function test_duplicated_routes_are_merged_and_without_origins_every_host_is_kept(): void
    {
        $result = SurfaceImport::parse($this->har([
            ['method' => 'get', 'url' => 'https://app.example.com/api/itens/1?a=1'],
            ['method' => 'GET', 'url' => 'https://app.example.com/api/itens/2?b=1', 'headers' => [['name' => 'cookie', 'value' => 'x']]],
            ['method' => 'GET', 'url' => 'https://app.example.com/api/itens/3?a=2'],
            ['method' => 'GET', 'url' => 'https://app.example.com/api/convites/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.Xy3'],
            ['method' => 'GET', 'url' => 'https://app.example.com/api/convites/77'],
        ]), null, self::ORIGINS);
        $this->assertSame([
            'GET /api/itens/1' => [['a', 'b'], [], true, false],
            'GET /api/convites/77' => [[], [], false, false],
        ], $this->table($result));

        $anywhere = SurfaceImport::parse($this->har([['method' => 'GET', 'url' => 'https://qualquer.example.net/api/itens']]));
        $this->assertSame([['method' => 'GET', 'path' => '/api/itens', 'host' => null, 'params' => [], 'body' => [], 'auth' => false, 'source' => 'har', 'template' => false]], $anywhere['endpoints']);
        $this->assertSame([], $anywhere['meta']['skipped_hosts']);
    }

    public function test_paths_are_normalized_to_the_endpoint_map_format(): void
    {
        $this->assertSame('/api/users/{id}', SurfaceImport::path('/api/users/{userId}'));
        $this->assertSame('/api/users/{id}/posts/{id}', SurfaceImport::path('/api/users/:id/posts/:postId'));
        $this->assertSame('/api/orgs/{id}/membros', SurfaceImport::path('/api/orgs/{{orgId}}/membros'));
        $this->assertSame('/api/pedidos/{id}', SurfaceImport::path('https://app.example.com/api/pedidos/123?x=1#y'));
        $this->assertSame('/api/docs/{id}', SurfaceImport::path('/api/docs/550E8400-E29B-41D4-A716-446655440000'));
        $this->assertSame('/api/reset/{id}', SurfaceImport::path('/api/reset/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'));
        $this->assertSame('/api/convites/{id}', SurfaceImport::path('/api/convites/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.Xy3'));
        $this->assertSame('/api/relatorio-anual-financeiro-consolidado', SurfaceImport::path('/api/relatorio-anual-financeiro-consolidado'));
        $this->assertSame('/api/v1/itens', SurfaceImport::path('api//v1/itens/'));
        $this->assertSame('/', SurfaceImport::path(''));
        $this->assertNull(SurfaceImport::path('/api/../admin'));
        $this->assertNull(SurfaceImport::path('/api/<script>'));
        $this->assertNull(SurfaceImport::path('/api/'.str_repeat('x', 400)));
    }

    public function test_limits_on_size_and_number_of_routes(): void
    {
        $paths = [];
        for ($i = 0; $i < 650; $i++) {
            $paths['/rota'.$i] = ['get' => []];
        }
        $result = SurfaceImport::parse(json_encode(['openapi' => '3.0.0', 'paths' => $paths]));

        $this->assertSame(600, $result['meta']['count']);
        $this->assertCount(600, $result['endpoints']);
        $this->assertStringContainsString('600', implode(' ', $result['meta']['warnings']));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('5 MB');
        SurfaceImport::parse(str_repeat(' ', SurfaceImport::MAX_BYTES + 1));
    }

    public function test_unknown_or_unreadable_documents_are_rejected_with_a_clear_message(): void
    {
        foreach (['{"foo": 1}', '{nao é json', '', '[1,2]', '{"swagger": "1.2", "paths": {}}'] as $content) {
            try {
                SurfaceImport::parse($content, 'arquivo.json');
                $this->fail('Documento aceito: '.$content);
            } catch (InvalidArgumentException $error) {
                $this->assertNotSame('', $error->getMessage());
            }
        }
    }

    public function test_merge_adds_imported_routes_to_the_inventory_keeping_their_source(): void
    {
        $merged = SurfaceImport::merge([
            'GET /api/users/{id}' => ['method' => 'GET', 'path' => '/api/users/{id}', 'params' => ['page'], 'body' => [], 'auth' => false, 'seen_in' => 'xhr'],
        ], [
            ['method' => 'GET', 'path' => '/api/users/{id}', 'host' => null, 'params' => ['expand'], 'body' => [], 'auth' => true, 'source' => 'openapi'],
            ['method' => 'POST', 'path' => '/auth/login', 'host' => 'api.example.com', 'params' => ['filtro[nome]', 'user.id'], 'body' => ['email'], 'auth' => false, 'source' => 'har'],
        ]);

        $this->assertSame([
            'GET /api/users/{id}' => [
                'method' => 'GET', 'path' => '/api/users/{id}', 'params' => ['page', 'expand'],
                'body' => [], 'auth' => true, 'seen_in' => 'xhr', 'source' => 'openapi', 'template' => true,
            ],
            'POST https://api.example.com/auth/login' => [
                'method' => 'POST', 'path' => 'https://api.example.com/auth/login', 'params' => ['filtro[nome]', 'user.id'],
                'body' => ['email'], 'auth' => false, 'seen_in' => 'import', 'source' => 'har',
            ],
        ], $merged);
    }

    public function test_agentic_selection_skips_imported_templates_but_keeps_them_in_the_inventory(): void
    {
        $inventory = SurfaceImport::merge([], SurfaceImport::parse(json_encode($this->openapi()), null, self::ORIGINS)['endpoints']);
        $inventory = SurfaceImport::merge($inventory, [
            ['method' => 'GET', 'path' => '/api/invoices/42', 'host' => null, 'params' => ['q'], 'body' => [], 'auth' => true, 'source' => 'har', 'template' => false],
        ]);

        $this->assertCount(5, $inventory);
        $this->assertTrue($inventory['GET https://api.example.com/v1/users/{id}']['template']);
        $this->assertArrayNotHasKey('template', $inventory['GET /api/invoices/42']);
        $selected = array_column(AgenticRun::selectTargets($inventory, 12), 'path');
        $this->assertSame(['/api/invoices/42', 'https://api.example.com/v1/orders', 'https://api.example.com/v1/health'], $selected);
    }

    private function schemaSpec(array $schemas, array $root): string
    {
        return json_encode(['openapi' => '3.0.0', 'components' => ['schemas' => $schemas], 'paths' => [
            '/api/x' => ['post' => ['requestBody' => ['content' => ['application/json' => ['schema' => $root]]]]],
        ]]);
    }

    public function test_schema_fan_out_through_refs_is_memoized_and_cycles_terminate(): void
    {
        $schemas = ['S6' => ['properties' => ['folha' => []], 'allOf' => [['$ref' => '#/components/schemas/S0']]]];
        for ($level = 0; $level < 6; $level++) {
            $schemas['S'.$level] = ['properties' => ['campo'.$level => []], 'allOf' => array_fill(0, 100, ['$ref' => '#/components/schemas/S'.($level + 1)])];
        }
        $started = microtime(true);

        $result = SurfaceImport::parse($this->schemaSpec($schemas, ['$ref' => '#/components/schemas/S0']));

        $this->assertLessThan(2.0, microtime(true) - $started);
        $this->assertSame(['campo0', 'campo1', 'campo2', 'campo3', 'campo4', 'campo5', 'folha'], $result['endpoints'][0]['body']);
        $this->assertSame([], $result['meta']['warnings']);
    }

    public function test_schema_traversal_stops_at_the_global_node_cap_with_a_warning(): void
    {
        $parts = array_map(fn ($index) => ['properties' => ['f'.$index => []]], range(1, 6000));
        $started = microtime(true);

        $result = SurfaceImport::parse($this->schemaSpec([], ['allOf' => $parts]));

        $this->assertLessThan(2.0, microtime(true) - $started);
        $this->assertSame(1, $result['meta']['count']);
        $this->assertStringContainsString(number_format(SurfaceImport::MAX_NODES, 0, ',', '.'), implode(' ', $result['meta']['warnings']));

        if (class_exists(Yaml::class)) {
            $yaml = "openapi: 3.0.0\nx-n0: &n0\n  properties: {f: {}}\n";
            for ($level = 1; $level <= 9; $level++) {
                $yaml .= "x-n{$level}: &n{$level}\n  allOf:\n".str_repeat('    - *n'.($level - 1)."\n", 10);
            }
            $yaml .= "paths:\n  /api/x:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: *n9\n";
            $started = microtime(true);
            $bomb = SurfaceImport::parse($yaml, 'bomba.yaml');
            $this->assertLessThan(2.0, microtime(true) - $started);
            $this->assertSame(['f'], $bomb['endpoints'][0]['body']);
            $this->assertNotSame([], $bomb['meta']['warnings']);
        }
    }
}
