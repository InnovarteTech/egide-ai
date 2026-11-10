<?php

namespace Tests\Feature;

use App\Models\Scan;
use App\Security\AgenticRun;
use Tests\TestCase;

class AgenticRunTest extends TestCase
{
    public function test_select_targets_prioritizes_api_and_skips_assets(): void
    {
        $inventory = [
            'GET /assets/app.css' => ['path' => '/assets/app.css', 'params' => [], 'body' => []],
            'GET /api/bookings/12' => ['path' => '/api/bookings/12', 'params' => [], 'body' => []],
            'GET /api/arenas' => ['path' => '/api/arenas', 'params' => ['q'], 'body' => []],
            'GET /home' => ['path' => '/home', 'params' => [], 'body' => []],
        ];
        $selected = AgenticRun::selectTargets($inventory, 2);
        $this->assertCount(2, $selected);
        $paths = array_column($selected, 'path');
        $this->assertContains('/api/arenas', $paths);
        $this->assertNotContains('/assets/app.css', $paths);
    }

    public function test_select_targets_keeps_a_graphql_endpoint_ahead_of_plain_pages(): void
    {
        $inventory = [];
        foreach (range(1, 12) as $page) {
            $inventory['GET /portal/tela'.$page] = ['path' => '/portal/tela'.$page, 'params' => [], 'body' => []];
        }
        $inventory['POST /servicos/graphql'] = ['method' => 'POST', 'path' => '/servicos/graphql', 'params' => [], 'body' => []];

        $this->assertContains('/servicos/graphql', array_column(AgenticRun::selectTargets($inventory, 12), 'path'));
    }

    public function test_should_probe_blocks_destructive_and_out_of_scope(): void
    {
        $scope = ['rules' => [['method' => '*', 'path' => '/', 'prefix' => true]], 'denied' => [], 'api' => null];
        $run = new AgenticRun($scope);
        $this->assertFalse($run->shouldProbe('/usuarios/excluir'));
        $this->assertFalse($run->shouldProbe('https://evil.com/x'));
        $this->assertTrue($run->shouldProbe('/api/bookings/12'));
    }

    public function test_auth_checks_fire_jwt_and_rate_when_present(): void
    {
        $inventory = ['POST /auth/login' => ['path' => '/auth/login'], 'GET /api/arenas' => ['path' => '/api/arenas']];

        $checks = AgenticRun::authChecks($inventory, 'eyJhbGc.payload.sig');
        $kinds = array_column($checks, 'check');
        $this->assertContains('jwt', $kinds);
        $this->assertContains('rate', $kinds);

        $noToken = AgenticRun::authChecks($inventory, null);
        $this->assertNotContains('jwt', array_column($noToken, 'check'));
        $this->assertContains('rate', array_column($noToken, 'check'));

        $this->assertSame([], AgenticRun::authChecks(['GET /x' => ['path' => '/x']], null));
    }

    public function test_auth_checks_only_match_login_submit_paths(): void
    {
        $inventory = [
            'POST /api/auth/login' => ['path' => '/api/auth/login'],
            'GET /api/auth/me' => ['path' => '/api/auth/me'],
            'GET /api/tenant/current' => ['path' => '/api/tenant/current'],
            'POST /admin/login' => ['path' => '/admin/login'],
        ];
        $paths = array_column(AgenticRun::authChecks($inventory, null), 'path');
        $this->assertContains('/api/auth/login', $paths);
        $this->assertContains('/admin/login', $paths);
        $this->assertNotContains('/api/auth/me', $paths);
        $this->assertNotContains('/api/tenant/current', $paths);
    }

    public function test_auth_checks_skip_destructive_auth_routes(): void
    {
        $inventory = [
            'POST /auth/logout' => ['path' => '/auth/logout'],
            'POST /oauth/revoke' => ['path' => '/oauth/revoke'],
            'POST /session/reset' => ['path' => '/session/reset'],
            'POST /auth/login' => ['path' => '/auth/login'],
        ];
        $paths = array_column(AgenticRun::authChecks($inventory, null), 'path');
        $this->assertContains('/auth/login', $paths);
        $this->assertNotContains('/auth/logout', $paths);
        $this->assertNotContains('/oauth/revoke', $paths);
        $this->assertNotContains('/session/reset', $paths);
    }

    public function test_budget_counters_stop_each_dimension(): void
    {
        $budget = ['max_endpoints' => 2, 'max_strategist_calls' => 3];
        $this->assertTrue(AgenticRun::withinBudget(['endpoints' => 1, 'strategist_calls' => 2], $budget));
        $this->assertFalse(AgenticRun::withinBudget(['endpoints' => 2, 'strategist_calls' => 0], $budget));
        $this->assertFalse(AgenticRun::withinBudget(['endpoints' => 0, 'strategist_calls' => 3], $budget));
    }

    public function test_budget_reads_defaults(): void
    {
        $budget = AgenticRun::budget(new Scan(['scope' => []]));
        $this->assertSame(12, $budget['max_endpoints']);
        $this->assertSame(40, $budget['max_strategist_calls']);
    }
}
