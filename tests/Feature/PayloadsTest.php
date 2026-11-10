<?php

namespace Tests\Feature;

use App\Security\Payloads;
use Tests\TestCase;

class PayloadsTest extends TestCase
{
    public function test_xss_payload_adapts_to_context(): void
    {
        $attr = Payloads::for('xss', 'query', ['context' => 'attr']);
        $this->assertNotEmpty($attr);
        $this->assertStringContainsString('">', $attr[0]['value']);
        $this->assertStringContainsString('egideXSS', $attr[0]['value']);
        $this->assertStringContainsString($attr[0]['marker'], $attr[0]['value']);

        $js = Payloads::for('xss', 'query', ['context' => 'js']);
        $this->assertStringContainsString('</script>', $js[0]['value']);
    }

    public function test_each_class_yields_payloads_with_oracle(): void
    {
        $map = ['xss' => 'injectionReflectedAssess', 'sqli_time' => 'injectionTimeAssess', 'ssrf' => 'ssrfAssess'];
        foreach ($map as $class => $oracle) {
            $items = Payloads::for($class, 'query');
            $this->assertNotEmpty($items, $class);
            foreach ($items as $item) {
                $this->assertSame($oracle, $item['oracle'], $class);
                $this->assertArrayHasKey('value', $item);
                $this->assertArrayHasKey('marker', $item);
            }
        }
    }

    public function test_sqli_time_payload_is_db_agnostic_sleep(): void
    {
        $joined = implode(' ', array_column(Payloads::for('sqli_time', 'query'), 'value'));
        $this->assertStringContainsStringIgnoringCase('sleep', $joined);
        $this->assertStringContainsString('pg_sleep', $joined);
    }

    public function test_marker_is_unique(): void
    {
        $this->assertNotSame(Payloads::marker('egideXSS'), Payloads::marker('egideXSS'));
    }

    public function test_wave2_classes_yield_payloads_with_oracle(): void
    {
        $map = ['sqli_error' => 'sqlErrorAssess', 'traversal' => 'traversalAssess', 'graphql' => 'graphqlAssess'];
        foreach ($map as $class => $oracle) {
            $items = Payloads::for($class, $class === 'graphql' ? 'body' : 'query');
            $this->assertNotEmpty($items, $class);
            foreach ($items as $item) {
                $this->assertSame($oracle, $item['oracle'], $class);
                $this->assertArrayHasKey('value', $item);
                $this->assertArrayHasKey('marker', $item);
            }
        }
    }

    public function test_traversal_payload_targets_passwd(): void
    {
        $joined = implode(' ', array_column(Payloads::for('traversal', 'query'), 'value'));
        $this->assertStringContainsString('etc/passwd', $joined);
    }

    public function test_graphql_payload_is_introspection_query(): void
    {
        $value = Payloads::for('graphql', 'body')[0]['value'];
        $this->assertStringContainsString('__schema', $value);
    }

    public function test_dom_xss_payload_embeds_execution_marker(): void
    {
        $items = Payloads::for('dom_xss', 'hash', ['token' => 'EGIDEDOMabc123']);
        $this->assertNotEmpty($items);
        $hasOnerror = false;
        foreach ($items as $item) {
            $this->assertSame('domXssAssess', $item['oracle']);
            $this->assertStringContainsString('EGIDEDOMabc123', $item['value']);
            $this->assertSame('EGIDEDOMabc123', $item['marker']);
            $hasOnerror = $hasOnerror || str_contains($item['value'], 'onerror');
        }
        $this->assertTrue($hasOnerror, 'deve ter variante img/onerror');
    }

    public function test_nosql_payload_has_operator(): void
    {
        $items = Payloads::for('nosql', 'query');
        $this->assertStringContainsString('$ne', implode(' ', array_column($items, 'value')));
        foreach ($items as $item) {
            $this->assertSame('noSqlAssess', $item['oracle']);
        }
    }
}
