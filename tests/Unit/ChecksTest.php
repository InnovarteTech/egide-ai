<?php

namespace Tests\Unit;

use App\Security\Checks;
use PHPUnit\Framework\TestCase;

class ChecksTest extends TestCase
{
    public function test_bases_cover_root_entry_and_parent_directory(): void
    {
        $this->assertSame(['/', '/h/app/login', '/h/app'], Checks::bases(['url' => 'https://staging.example.com/h/app/login']));
        $this->assertSame(['/', '/vulneravel'], Checks::bases(['url' => 'http://lab.egide.test:8788/vulneravel/']));
    }

    public function test_tokens_and_ids_in_paths_are_normalized(): void
    {
        $this->assertSame('/conta/:id/redefinir/:id', Checks::normalizePath('/conta/4821/redefinir/9f86d081884c7d659a2feaa0c55ad015'));
        $this->assertSame('/h/:id/painel', Checks::normalizePath('/h/7b263db1e3282d207274/painel'));
        $this->assertSame('/faturas/exportar', Checks::normalizePath('/faturas/exportar'));
    }

    public function test_sensitive_files_need_non_html_content_and_enough_signatures(): void
    {
        $sql = Checks::FILES['backup.sql'];
        $env = Checks::FILES['.env'];

        $this->assertFalse(Checks::confirmed($sql, ['status' => 200, 'matches' => ['CREATE TABLE'], 'type' => 'text/plain']));
        $this->assertTrue(Checks::confirmed($sql, ['status' => 200, 'matches' => ['CREATE TABLE', 'INSERT INTO'], 'type' => 'application/sql']));
        $this->assertFalse(Checks::confirmed($env, ['status' => 200, 'matches' => ['APP_KEY='], 'type' => 'text/html; charset=utf-8']));
        $this->assertTrue(Checks::confirmed($env, ['status' => 200, 'matches' => ['APP_KEY='], 'type' => 'text/plain']));
        $this->assertFalse(Checks::confirmed($env, ['status' => 200, 'matches' => ['APP_KEY='], 'type' => 'text/plain', 'blocked' => true]));
    }

    public function test_openapi_spec_is_confirmed_only_with_two_signatures_and_a_non_html_type(): void
    {
        $spec = Checks::FILES['swagger.json'];

        $this->assertSame('medium', $spec['severity']);
        $this->assertFalse(Checks::confirmed($spec, ['status' => 200, 'matches' => ['"openapi"'], 'type' => 'application/json']));
        $this->assertTrue(Checks::confirmed($spec, ['status' => 200, 'matches' => ['"openapi"', '"paths"'], 'type' => 'application/json']));
        // Uma página HTML do Swagger UI (não a especificação) não conta.
        $this->assertFalse(Checks::confirmed($spec, ['status' => 200, 'matches' => ['"openapi"', '"paths"'], 'type' => 'text/html; charset=utf-8']));
    }

    public function test_header_issues_become_grouped_findings_without_secret_values(): void
    {
        $findings = Checks::headerFindings([
            'hsts' => ['/login' => true, '/painel' => true],
            'version:nginx/1.18.0' => ['/login' => true],
            'cookie:session:secure,samesite' => ['/login' => true],
        ]);

        $titles = array_column($findings, 'title');
        $this->assertContains('HSTS ausente nas respostas HTTPS', $titles);
        $this->assertContains('Servidor revela a versão do software', $titles);
        $this->assertContains('Cookie session sem atributos de proteção', $titles);
        $cookie = $findings[array_search('Cookie session sem atributos de proteção', $titles)];
        $this->assertSame('medium', $cookie['severity']);
        $this->assertStringContainsString('Observado em 2 respostas', $findings[array_search('HSTS ausente nas respostas HTTPS', $titles)]['evidence']['detail']);
    }

    public function test_every_check_and_finding_carries_a_classification_reference(): void
    {
        foreach ([...Checks::FILES, ...Checks::HEADERS] as $check) {
            $this->assertMatchesRegularExpression('~^OWASP A\d{2}:2021 · CWE-\d+$~', $check['reference']);
        }

        $findings = Checks::headerFindings([
            'clickjacking' => ['/login' => true],
            'cookie:session:secure,samesite' => ['/login' => true],
            'cookie:prefs:samesite' => ['/login' => true],
        ]);

        $references = array_column(array_column($findings, 'evidence'), 'reference');
        $this->assertSame(['OWASP A05:2021 · CWE-1021', 'OWASP A05:2021 · CWE-614', 'OWASP A05:2021 · CWE-1275'], $references);
    }

    public function test_sensitive_file_probes_are_recognised_at_any_base(): void
    {
        $this->assertTrue(Checks::isProbe('/.git/HEAD'));
        $this->assertTrue(Checks::isProbe('/login/.env'));
        $this->assertFalse(Checks::isProbe('/api/clients/list'));
        $this->assertFalse(Checks::isProbe('/environment'));
    }

    public function test_cvss_scores_by_severity(): void
    {
        $this->assertSame(9.8, Checks::cvss('critical')['score']);
        $this->assertSame('Crítico', Checks::cvss('critical')['rating']);
        $this->assertSame(7.5, Checks::cvss('high')['score']);
        $this->assertSame(3.1, Checks::cvss('low')['score']);
        $this->assertSame('Informativo', Checks::cvss('x')['rating']);
    }
}
