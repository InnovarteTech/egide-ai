<?php

namespace Tests\Feature;

use App\Models\Scan;
use App\Security\Planner;
use Tests\TestCase;

class PlannerTest extends TestCase
{
    public function test_planner_routes_navigator_role_to_nav_model(): void
    {
        $scan = new Scan(['model' => 'claude-sonnet-5-5', 'scope' => ['nav_model' => 'claude-haiku-5-5']]);
        $this->assertSame('claude-haiku-5-5', Planner::modelFor($scan, 'navigator'));
        $this->assertSame('claude-sonnet-5-5', Planner::modelFor($scan, 'strategist'));

        $noNav = new Scan(['model' => 'claude-sonnet-5-5', 'scope' => []]);
        $this->assertSame('claude-sonnet-5-5', Planner::modelFor($noNav, 'navigator'));
    }
}
