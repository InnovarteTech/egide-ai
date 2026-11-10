<?php

namespace Tests\Feature;

use App\Security\EndpointMap;
use Tests\TestCase;

class EndpointMapTest extends TestCase
{
    public function test_merge_builds_structured_inventory(): void
    {
        $inv = EndpointMap::merge([], ['method' => 'GET', 'path' => '/api/bookings?status=x&page=2', 'host' => 'api.x', 'auth' => true]);
        $inv = EndpointMap::merge($inv, ['method' => 'POST', 'path' => '/api/bookings', 'host' => 'api.x', 'body' => ['arena_id' => 1, 'data' => '2026-01-01'], 'auth' => true]);
        $inv = EndpointMap::merge($inv, ['method' => 'GET', 'path' => '/api/bookings?status=y', 'host' => 'api.x']);

        $this->assertArrayHasKey('GET /api/bookings', $inv);
        $this->assertArrayHasKey('POST /api/bookings', $inv);
        $this->assertSame(['status', 'page'], $inv['GET /api/bookings']['params']);
        $this->assertSame(['arena_id', 'data'], $inv['POST /api/bookings']['body']);
        $this->assertTrue($inv['GET /api/bookings']['auth']);
        $this->assertSame('/api/bookings', $inv['GET /api/bookings']['path']);
    }

    public function test_from_bundle_extracts_api_routes(): void
    {
        $js = <<<'JS'
        const a = fetch("/api/arenas/"+id); axios.post("/api/reservas", body);
        import logo from "/assets/logo.png"; const css = "/build/app.css";
        fetch(`/api/stats/summary`); const n = "/api/bookings/12";
        JS;
        $routes = EndpointMap::fromBundle($js, 'https://api.x');

        $this->assertContains('/api/arenas/{id}', $routes);
        $this->assertContains('/api/reservas', $routes);
        $this->assertContains('/api/stats/summary', $routes);
        $this->assertContains('/api/bookings/{id}', $routes);
        $this->assertNotContains('/assets/logo.png', $routes);
        $this->assertNotContains('/build/app.css', $routes);
    }

    public function test_qualify_prefixes_scheme_only_for_cross_host(): void
    {
        $this->assertSame('/api/bookings', EndpointMap::qualify('app.example.com', 'app.example.com', '/api/bookings'));
        $this->assertSame('https://api.example.com/api/bookings', EndpointMap::qualify('api.example.com', 'app.example.com', '/api/bookings'));
    }
}
