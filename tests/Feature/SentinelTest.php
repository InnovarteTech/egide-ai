<?php

namespace Tests\Feature;

use App\Jobs\NotifyAlert;
use App\Models\Alert;
use App\Models\Monitor;
use App\Models\MonitorEvent;
use App\Models\User;
use App\Sentinel\Detector;
use App\Sentinel\Ingest;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class SentinelTest extends TestCase
{
    use RefreshDatabase;

    private function monitor(?User $user = null, ?string $webhook = null): array
    {
        $key = Monitor::issueKey();
        $monitor = Monitor::create([
            'user_id' => ($user ?? User::factory()->create())->id, 'name' => 'App de teste',
            'key_hash' => Monitor::hashKey($key), 'key_prefix' => substr($key, 0, 12), 'webhook_url' => $webhook,
        ]);

        return [$monitor, $key];
    }

    private function subject(string $email): string
    {
        return hash('sha256', $email);
    }

    public function test_ingest_requires_a_valid_key(): void
    {
        $this->postJson('/api/sentinela/eventos', ['events' => [['type' => 'login_failed', 'ip' => '203.0.113.7']]])->assertStatus(401);
        $this->withToken('esc_invalida')->postJson('/api/sentinela/eventos', ['events' => [['type' => 'login_failed', 'ip' => '203.0.113.7']]])->assertStatus(401);
        $this->assertSame(0, MonitorEvent::count());
    }

    public function test_ingest_accepts_events_and_rejects_plain_text_identities(): void
    {
        [$monitor, $key] = $this->monitor();

        $this->withToken($key)->postJson('/api/sentinela/eventos', ['events' => [
            ['type' => 'login_failed', 'ip' => '203.0.113.7', 'path' => '/login?next=/painel', 'status' => 401, 'subject' => $this->subject('a@x.com')],
        ]])->assertStatus(202)->assertJson(['accepted' => 1]);

        $event = MonitorEvent::sole();
        $this->assertSame('/login', $event->path);
        $this->assertSame($monitor->id, $event->monitor_id);
        $this->assertNotNull($monitor->fresh()->last_event_at);

        $this->withToken($key)->postJson('/api/sentinela/eventos', ['events' => [
            ['type' => 'login_failed', 'ip' => '203.0.113.7', 'subject' => 'pessoa@empresa.com'],
        ]])->assertStatus(422);
        $this->withToken($key)->postJson('/api/sentinela/eventos', ['events' => [
            ['type' => 'apagar_tudo', 'ip' => '203.0.113.7'],
        ]])->assertStatus(422);
        $this->assertSame(1, MonitorEvent::count());
    }

    public function test_brute_force_from_one_ip_raises_a_single_deduplicated_alert(): void
    {
        Queue::fake();
        [$monitor] = $this->monitor(webhook: 'https://hooks.example.com/egide');
        $ingest = app(Ingest::class);
        $burst = array_fill(0, Detector::BRUTE_FORCE, ['type' => 'login_failed', 'ip' => '198.51.100.20', 'subject' => $this->subject('alvo@x.com')]);

        $ingest->accept($monitor, $burst);
        $ingest->accept($monitor, $burst);

        $alert = Alert::where('rule', 'brute_force')->sole();
        $this->assertSame('high', $alert->severity);
        $this->assertSame('198.51.100.20', $alert->ip);
        $this->assertSame(2 * Detector::BRUTE_FORCE, $alert->count);
        $this->assertSame(1, Queue::pushed(NotifyAlert::class, fn (NotifyAlert $job) => $job->alertId === $alert->id)->count());
        $this->assertSame(Alert::count(), Queue::pushed(NotifyAlert::class)->count());
    }

    public function test_credential_stuffing_and_takeover_are_detected(): void
    {
        [$monitor] = $this->monitor();
        $ingest = app(Ingest::class);
        $victim = $this->subject('vitima@x.com');

        $ingest->accept($monitor, array_map(fn ($index) => [
            'type' => 'login_failed', 'ip' => '192.0.2.50', 'subject' => $this->subject("conta{$index}@x.com"),
        ], range(1, Detector::STUFFING_ACCOUNTS)));
        $this->assertTrue(Alert::where('rule', 'credential_stuffing')->exists());

        $ingest->accept($monitor, array_fill(0, Detector::TAKEOVER_FAILURES, ['type' => 'login_failed', 'ip' => '192.0.2.77', 'subject' => $victim]));
        $ingest->accept($monitor, [['type' => 'login_succeeded', 'ip' => '192.0.2.77', 'subject' => $victim]]);
        $takeover = Alert::where('rule', 'takeover_suspect')->sole();
        $this->assertSame('critical', $takeover->severity);
        $this->assertSame($victim, $takeover->subject);
    }

    public function test_normal_traffic_does_not_raise_alerts(): void
    {
        [$monitor] = $this->monitor();
        $ingest = app(Ingest::class);
        foreach (range(1, 6) as $index) {
            $ingest->accept($monitor, [
                ['type' => 'login_failed', 'ip' => "203.0.113.{$index}", 'subject' => $this->subject("u{$index}@x.com")],
                ['type' => 'login_succeeded', 'ip' => "203.0.113.{$index}", 'subject' => $this->subject("u{$index}@x.com")],
                ['type' => 'access_denied', 'ip' => "203.0.113.{$index}", 'path' => '/admin', 'status' => 403],
            ]);
        }

        $this->assertSame(0, Alert::count());
    }

    public function test_failure_spike_above_the_daily_baseline_is_an_anomaly(): void
    {
        [$monitor] = $this->monitor();
        foreach (range(1, 40) as $hourStep) {
            MonitorEvent::create([
                'monitor_id' => $monitor->id, 'type' => 'login_failed', 'ip' => '203.0.113.9',
                'occurred_at' => now()->subMinutes(30 * $hourStep),
            ]);
        }
        $spike = array_map(fn ($index) => ['type' => 'login_failed', 'ip' => "198.51.100.{$index}"], range(1, 12));

        app(Ingest::class)->accept($monitor, $spike);

        $this->assertTrue(Alert::where('rule', 'failure_anomaly')->exists());
    }

    public function test_monitors_are_isolated_between_accounts(): void
    {
        [$monitor] = $this->monitor();
        $alert = Alert::create([
            'monitor_id' => $monitor->id, 'rule' => 'brute_force', 'severity' => 'high', 'title' => 'x', 'detail' => 'y',
            'fingerprint' => str_repeat('a', 64), 'first_seen_at' => now(), 'last_seen_at' => now(),
        ]);
        $other = User::factory()->create();

        $this->actingAs($other)->get('/sentinela/'.$monitor->id)->assertNotFound();
        $this->actingAs($other)->post('/alertas/'.$alert->id.'/status')->assertNotFound();
        $this->actingAs($other)->delete('/sentinela/'.$monitor->id)->assertNotFound();
        $this->assertSame('open', $alert->fresh()->status);
    }

    public function test_key_is_shown_once_and_only_its_hash_is_stored(): void
    {
        $user = User::factory()->create();
        $response = $this->actingAs($user)->post('/sentinela', ['name' => 'Produção']);
        $monitor = Monitor::sole();
        $response->assertRedirect('/sentinela/'.$monitor->id)->assertSessionHas('monitor_key');
        $key = session('monitor_key');

        $this->assertSame(Monitor::hashKey($key), $monitor->key_hash);
        $this->assertStringNotContainsString($key, json_encode($monitor->fresh()->toArray()));
        $this->withToken($key)->postJson('/api/sentinela/eventos', ['events' => [['type' => 'login_succeeded', 'ip' => '203.0.113.1']]])->assertStatus(202);
    }

    public function test_webhook_must_be_public_https(): void
    {
        $user = User::factory()->create();
        [$monitor] = $this->monitor($user);

        foreach (['http://hooks.example.com/x', 'https://127.0.0.1/x', 'https://user:pw@hooks.example.com/x', 'https://localhost/x'] as $url) {
            $this->actingAs($user)->put('/sentinela/'.$monitor->id, ['name' => 'App', 'webhook_url' => $url])->assertSessionHasErrors('webhook_url');
        }
        $this->actingAs($user)->put('/sentinela/'.$monitor->id, ['name' => 'App', 'webhook_url' => 'https://hooks.example.com/x'])->assertSessionHasNoErrors();
        $this->assertSame('https://hooks.example.com/x', $monitor->fresh()->webhook_url);
    }

    public function test_suspended_accounts_cannot_ingest(): void
    {
        $user = User::factory()->create();
        [, $key] = $this->monitor($user);
        $user->forceFill(['suspended_at' => now()])->save();

        $this->withToken($key)->postJson('/api/sentinela/eventos', ['events' => [['type' => 'login_failed', 'ip' => '203.0.113.7']]])->assertStatus(401);
        $this->assertSame(0, MonitorEvent::count());
    }
}
