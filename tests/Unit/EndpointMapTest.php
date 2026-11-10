<?php

namespace Tests\Unit;

use App\Security\EndpointMap;
use PHPUnit\Framework\TestCase;

class EndpointMapTest extends TestCase
{
    public function test_from_bundle_extracts_api_routes_and_normalizes_numeric_ids(): void
    {
        $js = <<<'JS'
        const BASE = "/api/v1";
        fetch("/api/faturas");
        fetch("/api/empresas/42/extratos");
        axios.get(`/graphql`);
        const css = "/assets/app.css";
        const img = "/static/logo.png";
        const home = "/painel";
        JS;

        $routes = EndpointMap::fromBundle($js, 'https://app.example.com');

        $this->assertContains('/api/faturas', $routes);
        $this->assertContains('/api/empresas/{id}/extratos', $routes);
        $this->assertContains('/graphql', $routes);
        // Assets e rotas de UI comuns ficam de fora.
        $this->assertNotContains('/assets/app.css', $routes);
        $this->assertNotContains('/static/logo.png', $routes);
        $this->assertNotContains('/painel', $routes);
    }

    public function test_from_bundle_ignores_static_assets_and_the_bare_api_root(): void
    {
        $routes = EndpointMap::fromBundle('"/api" + "/api/dados.json" + "/vendor/chunk.js"', 'https://app.example.com');

        $this->assertNotContains('/api', $routes);
        $this->assertNotContains('/api/dados.json', $routes);
        $this->assertNotContains('/vendor/chunk.js', $routes);
    }

    public function test_merge_accumulates_params_and_auth_without_duplicating_the_route(): void
    {
        $inventory = EndpointMap::merge([], ['method' => 'get', 'path' => '/api/faturas?page=1', 'auth' => false]);
        $inventory = EndpointMap::merge($inventory, ['method' => 'GET', 'path' => '/api/faturas?filtro=ativos', 'auth' => true]);

        $this->assertCount(1, $inventory);
        $entry = $inventory['GET /api/faturas'];
        $this->assertSame(['page', 'filtro'], $entry['params']);
        $this->assertTrue($entry['auth']);
    }
}
