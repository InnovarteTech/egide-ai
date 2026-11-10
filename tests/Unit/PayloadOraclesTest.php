<?php

namespace Tests\Unit;

use App\Security\PayloadOracles;
use PHPUnit\Framework\TestCase;

class PayloadOraclesTest extends TestCase
{
    private const ROWS = '{"pedidos":[{"id":"1","item":"Assinatura anual"}]}';

    private const NONE = '{"pedidos":[]}';

    private const TRUE_PAYLOAD = "1' AND '1'='1'-- -";

    public function test_sql_error_oracle_detects_db_error_signatures(): void
    {
        $falha = PayloadOracles::sqlErrorAssess('/busca', 'Fatal error: SQLSTATE[42000]: Syntax error or access violation near "\'"');
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('high', $falha['finding']['severity']);
        $this->assertSame('nao_testado', PayloadOracles::sqlErrorAssess('/busca', '{"results":[]}')['verdict']);
        // Não-SQL contendo "syntax error" (erro de parser PHP, tutorial) não é SQLi.
        $this->assertSame('nao_testado', PayloadOracles::sqlErrorAssess('/busca', 'Parse error: syntax error, unexpected T_STRING in /app.php on line 5')['verdict']);
        // Erro real de SQL (SQL syntax) ainda é pego.
        $this->assertSame('falha', PayloadOracles::sqlErrorAssess('/busca', 'You have an error in your SQL syntax; check the manual')['verdict']);
    }

    public function test_traversal_oracle_detects_system_file(): void
    {
        $falha = PayloadOracles::traversalAssess('/arquivo', "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:");
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('high', $falha['finding']['severity']);
        $this->assertSame('falha', PayloadOracles::traversalAssess('/arquivo', "; for 16-bit app support\n[fonts]")['verdict']);
        $this->assertSame('nao_testado', PayloadOracles::traversalAssess('/arquivo', 'arquivo nao encontrado')['verdict']);
        // INI genérico (não win.ini) não é travessia.
        $this->assertSame('nao_testado', PayloadOracles::traversalAssess('/arquivo', "[extensions]\nfoo=bar")['verdict']);
    }

    public function test_graphql_oracle_detects_introspection(): void
    {
        $falha = PayloadOracles::graphqlAssess('/graphql', '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}');
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('medium', $falha['finding']['severity']);
        $this->assertSame('protegido', PayloadOracles::graphqlAssess('/graphql', '{"errors":[{"message":"introspection is disabled"}]}')['verdict']);
        // Erro de validação citando __schema (introspecção desligada) não é falha.
        $this->assertSame('protegido', PayloadOracles::graphqlAssess('/graphql', '{"errors":[{"message":"Cannot query field __schema","extensions":{"exception":{"name":"ValidationError"}}}]}')['verdict']);
    }

    public function test_graphql_oracle_does_not_call_a_non_graphql_answer_protected(): void
    {
        $this->assertSame('nao_testado', PayloadOracles::graphqlAssess('/graphql', '<h1>Rota indisponível</h1>')['verdict']);
        $this->assertSame('nao_testado', PayloadOracles::graphqlAssess('/graphql', 'Fora do escopo autorizado pela Égide AI')['verdict']);
    }

    public function test_dom_xss_oracle_confirms_browser_execution(): void
    {
        $falha = PayloadOracles::domXssAssess('EGIDEDOMx1', ['executed' => true, 'token' => 'EGIDEDOMx1']);
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('high', $falha['finding']['severity']);
        $this->assertSame('InjectionCheck · DOM XSS', $falha['finding']['category']);
        $this->assertSame('nao_testado', PayloadOracles::domXssAssess('EGIDEDOMx1', ['executed' => false])['verdict']);
        $this->assertSame('nao_testado', PayloadOracles::domXssAssess('EGIDEDOMx1', ['executed' => true, 'token' => 'outro'])['verdict']);
    }

    public function test_stack_trace_oracle_detects_framework_traces(): void
    {
        $laravel = "Whoops\\Exception\\ErrorException: Undefined variable \$x in /var/www/vendor/laravel/framework/src/Illuminate/Routing/Controller.php:54\nStack trace:\n#0 /var/www/app/Http/Controllers/HomeController.php(21): handle()";
        $falha = PayloadOracles::stackTraceAssess('/painel', $laravel);
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('medium', $falha['finding']['severity']);
        $this->assertSame('ConfigCheck · rastro de pilha', $falha['finding']['category']);
        $this->assertSame('OWASP A05:2021 · CWE-209', $falha['finding']['evidence']['reference']);

        $python = "Traceback (most recent call last):\n  File \"/srv/app/views.py\", line 88, in get\n    raise KeyError(k)\nKeyError: 'id'";
        $this->assertSame('falha', PayloadOracles::stackTraceAssess('/x', $python)['verdict']);

        $java = "java.lang.NullPointerException\n\tat com.acme.Svc.run(Svc.java:42)\n\tat com.acme.Main.main(Main.java:11)";
        $this->assertSame('falha', PayloadOracles::stackTraceAssess('/x', $java)['verdict']);
    }

    public function test_stack_trace_oracle_does_not_flag_ordinary_text(): void
    {
        $this->assertSame('nao_testado', PayloadOracles::stackTraceAssess('/x', '{"erro":"id invalido"}')['verdict']);
        $this->assertSame('nao_testado', PayloadOracles::stackTraceAssess('/x', 'Ocorreu um erro. Tente novamente mais tarde.')['verdict']);
        // Menção à expressão "stack trace" na documentação, sem o rastro em si, não é vazamento.
        $this->assertSame('nao_testado', PayloadOracles::stackTraceAssess('/x', 'Veja o stack trace no console do navegador para depurar.')['verdict']);
        // Frase com "at" não é stack trace Java.
        $this->assertSame('nao_testado', PayloadOracles::stackTraceAssess('/x', 'Meet me at the station at 9.')['verdict']);
        // Resposta legítima que apenas cita um namespace de framework (sem rastro/linha) não é vazamento.
        $this->assertSame('nao_testado', PayloadOracles::stackTraceAssess('/x', '{"classe":"Illuminate\\\\Support\\\\Collection","itens":3}')['verdict']);
        $this->assertSame('nao_testado', PayloadOracles::stackTraceAssess('/x', 'Erro: a classe Symfony\Component\HttpKernel não foi encontrada no container.')['verdict']);
    }

    public function test_nosql_oracle_detects_error_signature(): void
    {
        $this->assertSame('falha', PayloadOracles::noSqlAssess('/x', 'MongoServerError: unknown top level operator $ne')['verdict']);
        $this->assertSame('nao_testado', PayloadOracles::noSqlAssess('/x', '{"results":[]}')['verdict']);
        // Menção genérica ao produto (stack/marketing) não é injeção.
        $this->assertSame('nao_testado', PayloadOracles::noSqlAssess('/x', 'Powered by Couchbase 7.0')['verdict']);
        // "unknown operator" nu (validador custom rejeitando entrada) não é vazamento de erro Mongo.
        $this->assertSame('nao_testado', PayloadOracles::noSqlAssess('/x', 'Error: unknown operator in filter')['verdict']);
    }

    private function response(int $status, string $sample, bool $blocked = false): array
    {
        return ['status' => $status, 'sample' => $sample, 'type' => 'application/json', 'blocked' => $blocked, 'matches' => [], 'marker' => null, 'elapsed' => 40];
    }

    private function stableBase(string $sample = self::ROWS): array
    {
        return [$this->response(200, $sample), $this->response(200, $sample)];
    }

    public function test_boolean_sqli_confirms_when_true_matches_base_and_false_changes_in_two_rounds(): void
    {
        $round = [$this->response(200, self::ROWS), $this->response(200, self::NONE)];

        $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $this->stableBase(), [$round, $round]);

        $this->assertSame('falha', $assessment['verdict']);
        $this->assertSame('InjectionCheck · SQLi booleano', $assessment['finding']['category']);
        $this->assertSame('high', $assessment['finding']['severity']);
        $this->assertSame('OWASP A03:2021 · CWE-89', $assessment['finding']['evidence']['reference']);
        $this->assertSame('/servicos/pedido', $assessment['finding']['evidence']['path']);
    }

    public function test_boolean_sqli_needs_a_second_round_before_claiming_falha(): void
    {
        $round = [$this->response(200, self::ROWS), $this->response(200, self::NONE)];

        $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $this->stableBase(), [$round]);

        $this->assertSame('nao_testado', $assessment['verdict']);
        $this->assertNull($assessment['finding']);
    }

    public function test_boolean_sqli_rejects_rounds_that_disagree(): void
    {
        $positive = [$this->response(200, self::ROWS), $this->response(200, self::NONE)];
        $negative = [$this->response(200, self::ROWS), $this->response(200, self::ROWS)];

        $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $this->stableBase(), [$positive, $negative]);

        $this->assertSame('protegido', $assessment['verdict']);
    }

    public function test_boolean_sqli_rejects_payload_that_breaks_the_query(): void
    {
        $round = [$this->response(200, self::NONE), $this->response(200, self::NONE)];

        $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $this->stableBase(), [$round, $round]);

        $this->assertSame('protegido', $assessment['verdict']);
    }

    public function test_boolean_sqli_does_not_flag_a_reflected_payload(): void
    {
        $page = fn (string $term, bool $escape) => '<p>Resultados para '.($escape ? htmlspecialchars($term, ENT_QUOTES) : $term).'</p><ul></ul>';
        foreach ([true, false] as $escape) {
            $base = $this->stableBase($page('1', $escape));
            $round = [$this->response(200, $page(self::TRUE_PAYLOAD, $escape)), $this->response(200, $page("1' AND '1'='2'-- -", $escape))];

            $assessment = PayloadOracles::booleanSqlAssess('/busca', self::TRUE_PAYLOAD, $base, [$round, $round]);

            $this->assertNotSame('falha', $assessment['verdict'], $escape ? 'escapado' : 'bruto');
        }
    }

    public function test_boolean_sqli_confirms_through_a_search_page_that_reflects_the_input(): void
    {
        $page = fn (string $term, bool $row) => '<p>Resultados para '.htmlspecialchars($term, ENT_QUOTES).'</p><ul>'.($row ? '<li>Pedido 1 · Assinatura anual · R$ 1.200,00</li>' : '').'</ul>';
        $base = [$this->response(200, $page('1', true)), $this->response(200, $page('1', true))];
        $round = [$this->response(200, $page(self::TRUE_PAYLOAD, true)), $this->response(200, $page("1' AND '1'='2'-- -", false))];

        $assessment = PayloadOracles::booleanSqlAssess('/busca', self::TRUE_PAYLOAD, $base, [$round, $round]);

        $this->assertSame('falha', $assessment['verdict']);
    }

    public function test_boolean_sqli_counts_a_status_flip_on_the_false_condition(): void
    {
        $base = [$this->response(200, self::ROWS.'n'), $this->response(200, self::ROWS.'nn')];
        $round = [$this->response(200, self::ROWS.'n'), $this->response(500, str_repeat('x', strlen(self::ROWS) + 1))];

        $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $base, [$round, $round]);

        $this->assertSame('falha', $assessment['verdict']);
    }

    public function test_boolean_sqli_ignores_a_few_bytes_of_jitter_between_conditions(): void
    {
        $base = [$this->response(200, self::ROWS.'n'), $this->response(200, self::ROWS.'nn')];
        $round = [$this->response(200, self::ROWS.'n'), $this->response(200, self::ROWS.'nnnnnn')];

        $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $base, [$round, $round]);

        $this->assertNotSame('falha', $assessment['verdict']);
    }

    public function test_boolean_sqli_catches_a_one_word_change_on_a_byte_stable_page(): void
    {
        $base = $this->stableBase('{"existe":true}');
        $round = [$this->response(200, '{"existe":true}'), $this->response(200, '{"existe":false}')];

        $assessment = PayloadOracles::booleanSqlAssess('/api/usuario/existe', self::TRUE_PAYLOAD, $base, [$round, $round]);

        $this->assertSame('falha', $assessment['verdict']);
    }

    public function test_boolean_sqli_does_not_trust_blocked_or_rate_limited_responses(): void
    {
        $blocked = [$this->response(200, self::ROWS), $this->response(403, 'Fora do escopo', true)];
        $limited = [$this->response(200, self::ROWS), $this->response(429, 'Too Many Requests')];

        foreach (['bloqueada' => $blocked, 'limitada' => $limited] as $label => $round) {
            $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $this->stableBase(), [$round, $round]);

            $this->assertSame('nao_testado', $assessment['verdict'], $label);
        }
    }

    public function test_boolean_sqli_on_a_noisy_page_is_not_tested_rather_than_safe(): void
    {
        $base = [$this->response(200, self::ROWS.str_repeat('n', 40)), $this->response(200, self::ROWS.str_repeat('n', 80))];
        $round = [$this->response(200, self::ROWS.str_repeat('n', 60)), $this->response(200, self::NONE.str_repeat('n', 60))];

        $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $base, [$round, $round]);

        $this->assertSame('nao_testado', $assessment['verdict']);
    }

    private function cutResponse(int $size): array
    {
        return [...$this->response(200, str_repeat('a', 2000)), 'size' => $size];
    }

    public function test_boolean_sqli_compares_the_full_body_size_when_the_sample_is_cut(): void
    {
        $base = [$this->cutResponse(5000), $this->cutResponse(5000)];
        $round = [$this->cutResponse(5000), $this->cutResponse(4950)];

        $assessment = PayloadOracles::booleanSqlAssess('/servicos/pedido', self::TRUE_PAYLOAD, $base, [$round, $round]);

        $this->assertSame('falha', $assessment['verdict']);
    }

    public function test_boolean_sqli_negative_on_a_cut_page_is_not_tested_rather_than_safe(): void
    {
        $base = [$this->cutResponse(5000), $this->cutResponse(5000)];
        $round = [$this->cutResponse(5000), $this->cutResponse(5000)];
        $legacy = [$this->response(200, str_repeat('a', 2000)), $this->response(200, str_repeat('a', 2000))];

        $this->assertSame('nao_testado', PayloadOracles::booleanSqlAssess('/p', self::TRUE_PAYLOAD, $base, [$round, $round])['verdict']);
        $this->assertSame('nao_testado', PayloadOracles::booleanSqlAssess('/p', self::TRUE_PAYLOAD, $legacy, [$legacy, $legacy])['verdict']);
    }

    public function test_boolean_round_reports_a_single_positive_round_so_the_caller_can_confirm_it(): void
    {
        $positive = [$this->response(200, self::ROWS), $this->response(200, self::NONE)];
        $negative = [$this->response(200, self::ROWS), $this->response(200, self::ROWS)];
        $blocked = [$this->response(200, self::ROWS), $this->response(403, 'x', true)];

        $this->assertSame('holds', PayloadOracles::booleanRound(self::TRUE_PAYLOAD, $this->stableBase(), $positive));
        $this->assertSame('fails', PayloadOracles::booleanRound(self::TRUE_PAYLOAD, $this->stableBase(), $negative));
        $this->assertSame('untestable', PayloadOracles::booleanRound(self::TRUE_PAYLOAD, $this->stableBase(), $blocked));
    }

    public function test_boolean_round_counts_size_in_utf16_units_like_the_browser(): void
    {
        $emoji = [...$this->response(200, '{"ok":"😀"}'), 'size' => 11];

        $this->assertSame('fails', PayloadOracles::booleanRound(self::TRUE_PAYLOAD, [$emoji, $emoji], [$emoji, $emoji]));
    }

    public function test_open_redirect_matches_the_request_path_of_a_path_point_probe(): void
    {
        $sent = '/ir/https%3A%2F%2Fegide-ab12cd34.invalid%2F';
        $event = $this->redirectEvent('/painel', 302, true, $sent);

        $this->assertSame('protegido', PayloadOracles::openRedirectAssess('/ir/{destino}', 'egide-ab12cd34.invalid', [$event], 'GET', $sent)['verdict']);
    }

    public function test_boolean_sqli_evidence_carries_the_method_that_was_sent(): void
    {
        $round = [$this->response(200, self::ROWS), $this->response(200, self::NONE)];

        $assessment = PayloadOracles::booleanSqlAssess('/api/pedido', self::TRUE_PAYLOAD, $this->stableBase(), [$round, $round], 'POST');

        $this->assertSame('POST', $assessment['finding']['evidence']['method']);
    }

    private function redirectEvent(string $location, int $status = 302, bool $allowed = true, string $path = '/retorno', string $host = 'app.example.com'): array
    {
        return ['method' => 'GET', 'host' => $host, 'path' => $path, 'status' => $status,
            'allowed' => $allowed, 'reason' => '', 'issues' => [], 'location' => $location];
    }

    public function test_open_redirect_only_counts_the_probed_request_as_answered(): void
    {
        $background = $this->redirectEvent('', 200, true, '/api/notificacoes');
        $this->assertSame('nao_testado', PayloadOracles::openRedirectAssess('/retorno', 'egide-ab12cd34.invalid', [$background])['verdict']);

        $apiProbe = $this->redirectEvent('/painel', 302, true, '/retorno', 'api.example.com');
        $this->assertSame('protegido', PayloadOracles::openRedirectAssess('https://api.example.com/retorno', 'egide-ab12cd34.invalid', [$apiProbe])['verdict']);
        $otherHost = $this->redirectEvent('/painel', 302, true, '/retorno', 'cdn.example.com');
        $this->assertSame('nao_testado', PayloadOracles::openRedirectAssess('https://api.example.com/retorno', 'egide-ab12cd34.invalid', [$otherHost])['verdict']);
    }

    public function test_open_redirect_evidence_carries_the_method_that_was_sent(): void
    {
        $assessment = PayloadOracles::openRedirectAssess('/entrar', 'egide-ab12cd34.invalid', [$this->redirectEvent('https://egide-ab12cd34.invalid/', 302, true, '/entrar')], 'POST');

        $this->assertSame('POST', $assessment['finding']['evidence']['method']);
    }

    public function test_open_redirect_confirms_a_location_on_the_canary_host(): void
    {
        $locations = [
            'https://egide-ab12cd34.invalid/',
            '//egide-ab12cd34.invalid/',
            '/\\egide-ab12cd34.invalid/',
            'https:/\\egide-ab12cd34.invalid',
            'https://app.example.com@egide-ab12cd34.invalid/x',
            "/\t/egide-ab12cd34.invalid/",
        ];
        foreach ($locations as $location) {
            $assessment = PayloadOracles::openRedirectAssess('/retorno', 'egide-ab12cd34.invalid', [$this->redirectEvent($location)]);

            $this->assertSame('falha', $assessment['verdict'], $location);
            $this->assertSame('RedirectCheck · open redirect', $assessment['finding']['category']);
            $this->assertSame('medium', $assessment['finding']['severity']);
            $this->assertSame('OWASP A01:2021 · CWE-601', $assessment['finding']['evidence']['reference']);
            $this->assertSame('egide-ab12cd34.invalid', $assessment['finding']['evidence']['redirect_host']);
        }
    }

    public function test_open_redirect_evidence_never_stores_the_raw_location(): void
    {
        $assessment = PayloadOracles::openRedirectAssess('/retorno', 'egide-ab12cd34.invalid', [$this->redirectEvent('https://egide-ab12cd34.invalid/cb?code=segredo-do-app')]);

        $this->assertSame('falha', $assessment['verdict']);
        $this->assertStringNotContainsString('segredo-do-app', json_encode($assessment['finding']));
    }

    public function test_open_redirect_ignores_redirects_that_stay_on_the_site(): void
    {
        $locations = [
            '/entrar?next=https://egide-ab12cd34.invalid/',
            'https://egide-ab12cd34.invalid.app.example.com/',
            'https://app.example.com/painel',
        ];
        foreach ($locations as $location) {
            $assessment = PayloadOracles::openRedirectAssess('/retorno', 'egide-ab12cd34.invalid', [$this->redirectEvent($location)]);

            $this->assertSame('protegido', $assessment['verdict'], $location);
        }
        $notRedirect = PayloadOracles::openRedirectAssess('/retorno', 'egide-ab12cd34.invalid', [$this->redirectEvent('https://egide-ab12cd34.invalid/', 200)]);
        $this->assertSame('protegido', $notRedirect['verdict']);
    }

    public function test_open_redirect_without_an_answered_request_is_not_tested(): void
    {
        $this->assertSame('nao_testado', PayloadOracles::openRedirectAssess('/retorno', 'egide-ab12cd34.invalid', [])['verdict']);
        $blocked = $this->redirectEvent('https://egide-ab12cd34.invalid/', 403, false);
        $this->assertSame('nao_testado', PayloadOracles::openRedirectAssess('/retorno', 'egide-ab12cd34.invalid', [$blocked])['verdict']);
    }
}
