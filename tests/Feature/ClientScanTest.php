<?php

namespace Tests\Feature;

use App\Security\ClientScan;
use Tests\TestCase;

class ClientScanTest extends TestCase
{
    public function test_sinks_finds_dangerous_react_sinks(): void
    {
        $js = 'const html = location.hash.slice(1); el.dangerouslySetInnerHTML={__html: html}; document.write(x); foo.innerHTML=bar;';
        $names = array_column(ClientScan::sinks($js), 'sink');
        $this->assertContains('dangerouslySetInnerHTML', $names);
        $this->assertContains('document.write', $names);
        $this->assertContains('innerHTML', $names);

        $this->assertSame([], ClientScan::sinks('const a = 1 + 2; console.log(a);'));
    }

    public function test_sinks_flag_source_proximity(): void
    {
        $withSource = ClientScan::sinks('var h = location.hash.slice(1); el.dangerouslySetInnerHTML = {__html: h};');
        $this->assertTrue($withSource[0]['source']);

        $noSource = ClientScan::sinks('const s = JSON.stringify(data); node.innerHTML = s;');
        $this->assertFalse($noSource[0]['source']);
    }

    public function test_query_reading_is_detected_only_when_the_code_reads_the_query(): void
    {
        $this->assertFalse(ClientScan::readsQuery('const r = decodeURIComponent(location.hash.slice(1)); el.innerHTML = r;'));
        $this->assertTrue(ClientScan::readsQuery("const q = new URLSearchParams(location.search).get('q');"));
        $this->assertTrue(ClientScan::readsQuery('const [params] = useSearchParams();'));
    }
}
