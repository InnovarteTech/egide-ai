<?php

namespace Tests\Unit;

use App\Jobs\RunScan;
use App\Models\Target;
use App\Security\Scope;
use Tests\TestCase;

class ScopeTest extends TestCase
{
    public function test_request_budget_is_generous_for_tests_and_capped_for_production(): void
    {
        $this->assertSame(600, Scope::budget('laboratory', null, 600));
        $this->assertSame(600, Scope::budget('retest', null, 5000));
        $this->assertSame(2000, Scope::budget('external', 'test', 2000));
        $this->assertSame(180, Scope::budget('external', 'production', 500));
        $this->assertSame(180, Scope::budget('external', null, 500));
        $this->assertSame(10, Scope::budget('external', 'test', 1));
    }

    public function test_session_length_follows_configuration(): void
    {
        config(['egide.session_minutes' => 45]);

        $this->assertSame(2700, (new RunScan('x'))->timeout);
    }

    public function test_account_origins_must_share_the_asset_domain(): void
    {
        $this->assertTrue(Scope::sibling('https://app.agenda.com.br', 'https://salao-a.agenda.com.br'));
        $this->assertTrue(Scope::sibling('https://app.agenda.com.br', 'https://app.agenda.com.br'));
        $this->assertTrue(Scope::sibling('https://agenda.com', 'https://salao.agenda.com'));
        $this->assertFalse(Scope::sibling('https://app.agenda.com.br', 'https://agenda.com.br.evil.com'));
        $this->assertFalse(Scope::sibling('https://app.agenda.com.br', 'https://outro-site.com.br'));
        $this->assertFalse(Scope::sibling('https://app.agenda.com.br', 'https://xagenda.com.br'));
        $this->assertFalse(Scope::sibling('https://empresa.com.br', 'https://qualquer-outro.com.br'));
        $this->assertTrue(Scope::sibling('https://empresa.com.br', 'https://cliente.empresa.com.br'));
    }

    public function test_launch_scope_opens_each_account_on_its_own_subdomain(): void
    {
        $target = new Target([
            'origin' => 'https://app.agenda.com.br', 'entry_path' => '/login', 'rules' => [], 'denied' => [],
            'credentials' => [
                'a' => ['email' => 'a@x.com', 'password' => 'x', 'origin' => 'https://salao-a.agenda.com.br'],
                'b' => ['email' => 'b@x.com', 'password' => 'y', 'origin' => null],
            ],
        ]);

        $scope = Scope::launch($target);
        $this->assertSame('https://salao-a.agenda.com.br/login', $scope['url']);
        $this->assertSame(['a' => 'https://salao-a.agenda.com.br/login', 'b' => 'https://app.agenda.com.br/login'], $scope['urls']);
        $this->assertSame(['https://app.agenda.com.br', 'https://salao-a.agenda.com.br'], Scope::origins($target));
    }

    public function test_single_origin_assets_keep_the_original_scope(): void
    {
        $target = new Target(['origin' => 'https://staging.empresa.com', 'entry_path' => '/', 'rules' => [], 'denied' => [], 'credentials' => null]);

        $this->assertSame('https://staging.empresa.com/', Scope::launch($target)['url']);
        $this->assertSame([], Scope::launch($target)['urls']);
    }

    public function test_local_targets_only_verify_in_local_mode(): void
    {
        $target = new Target([
            'origin' => 'https://app.local.egide.test', 'entry_path' => '/', 'rules' => [], 'denied' => [], 'local_port' => 8099,
            'credentials' => ['a' => ['email' => 'a@x', 'password' => 'x', 'origin' => 'https://salao-a.local.egide.test']],
        ]);

        config(['egide.local_targets' => true]);
        $this->assertFalse(Scope::verify($target));

        $this->app['env'] = 'local';
        $this->assertTrue(Scope::verify($target));
        $this->assertSame(8099, Scope::launch($target)['local_port']);

        $target->credentials = ['a' => ['email' => 'a@x', 'password' => 'x', 'origin' => 'https://externo.empresa.com']];
        $this->assertFalse(Scope::verify($target));

        config(['egide.local_targets' => false]);
        $target->credentials = null;
        $this->assertFalse(Scope::verify($target));
    }
}
