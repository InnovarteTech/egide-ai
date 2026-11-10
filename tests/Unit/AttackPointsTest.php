<?php

namespace Tests\Unit;

use App\Security\AttackPoints;
use PHPUnit\Framework\TestCase;

class AttackPointsTest extends TestCase
{
    public function test_baseline_covers_params_ids_and_auth(): void
    {
        $booking = AttackPoints::baseline(['method' => 'GET', 'path' => '/api/bookings/{id}', 'params' => ['status'], 'body' => []]);
        $this->assertContains(['class' => 'idor', 'point' => 'path', 'key' => 'id'], $booking);
        $this->assertContains(['class' => 'xss', 'point' => 'query', 'key' => 'status'], $booking);
        $this->assertContains(['class' => 'sqli_time', 'point' => 'query', 'key' => 'status'], $booking);

        $login = AttackPoints::baseline(['method' => 'POST', 'path' => '/auth/login', 'params' => [], 'body' => ['email', 'senha']]);
        $classes = array_column($login, 'class');
        $this->assertContains('rate', $classes);
        $this->assertContains('jwt', $classes);

        $withUrl = AttackPoints::baseline(['path' => '/api/integrador', 'params' => ['url'], 'body' => []]);
        $this->assertContains(['class' => 'ssrf', 'point' => 'query', 'key' => 'url'], $withUrl);
    }

    public function test_baseline_adds_wave2_classes(): void
    {
        $withFile = AttackPoints::baseline(['path' => '/api/arquivos', 'params' => ['file'], 'body' => []]);
        $classes = array_column($withFile, 'class');
        $this->assertContains('sqli_error', $classes);
        $this->assertContains('traversal', $classes);

        $plain = AttackPoints::baseline(['path' => '/api/busca', 'params' => ['q'], 'body' => []]);
        $this->assertNotContains('traversal', array_column($plain, 'class'));

        $gql = AttackPoints::baseline(['path' => '/graphql', 'params' => [], 'body' => []]);
        $this->assertContains(['class' => 'graphql', 'point' => 'body', 'key' => 'query'], $gql);
    }

    public function test_baseline_adds_boolean_sqli_and_open_redirect_on_redirect_params(): void
    {
        $byId = AttackPoints::baseline(['path' => '/api/pedidos', 'params' => ['id'], 'body' => []]);
        $this->assertContains(['class' => 'sqli_bool', 'point' => 'query', 'key' => 'id'], $byId);
        $this->assertNotContains('open_redirect', array_column($byId, 'class'));

        foreach (['next', 'redirect_uri', 'returnTo', 'destino', 'r'] as $param) {
            $plan = AttackPoints::baseline(['path' => '/conta', 'params' => [$param], 'body' => []]);
            $this->assertContains(['class' => 'open_redirect', 'point' => 'query', 'key' => $param], $plan, $param);
        }
        foreach (['order', 'router', 'status'] as $param) {
            $plan = AttackPoints::baseline(['path' => '/conta', 'params' => [$param], 'body' => []]);
            $this->assertNotContains('open_redirect', array_column($plan, 'class'), $param);
        }
    }

    public function test_attacks_suggested_by_the_parameter_name_run_before_generic_fuzzing(): void
    {
        $redirect = array_column(AttackPoints::baseline(['path' => '/retorno', 'params' => ['destino'], 'body' => []]), 'class');
        $file = array_column(AttackPoints::baseline(['path' => '/baixar', 'params' => ['arquivo'], 'body' => []]), 'class');

        $this->assertLessThan(array_search('xss', $redirect), array_search('open_redirect', $redirect));
        $this->assertLessThan(array_search('xss', $redirect), array_search('ssrf', $redirect));
        $this->assertLessThan(array_search('xss', $file), array_search('traversal', $file));
    }

    public function test_every_baseline_class_is_one_the_ai_may_also_propose(): void
    {
        $endpoint = ['path' => '/api/auth/graphql/{id}', 'params' => ['next', 'file', 'q'], 'body' => ['email']];

        foreach (array_unique(array_column(AttackPoints::baseline($endpoint), 'class')) as $class) {
            $this->assertContains($class, AttackPoints::CLASSES, $class);
        }
    }

    public function test_attack_plan_merges_baseline_even_if_ai_empty(): void
    {
        $baseline = AttackPoints::baseline(['path' => '/api/bookings/{id}', 'params' => ['status'], 'body' => []]);
        $merged = AttackPoints::merge($baseline, []);
        $this->assertContains(['class' => 'idor', 'point' => 'path', 'key' => 'id'], $merged);
        $this->assertCount(count($merged), AttackPoints::merge($merged, $baseline));
    }
}
