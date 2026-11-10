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
}
