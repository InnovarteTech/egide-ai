<?php

namespace Tests\Feature;

use App\Jobs\RunScan;
use App\Models\CollaboratorHit;
use App\Security\Hunter;
use App\Security\Planner;

class FakeRunScan extends RunScan
{
    public bool $vulnerable = true;

    public bool $escaping = false;

    public int $navigationCost = 1;

    public array $frames = [];

    public array $sent = [];

    public ?Hunter $scriptedHunter = null;

    public array $gotos = [];

    public ?array $halt = null;

    public array $calls = [];

    private array $log = [];

    protected function hunter(Planner $planner): Hunter
    {
        return $this->scriptedHunter ?? parent::hunter($planner);
    }

    protected function settle(): void {}

    protected function runner(string $path, array $data = []): array
    {
        $this->calls[] = [$path, $data];
        $response = $this->respond($path, $data);
        if ($this->halt !== null && in_array($path, ['/observe', '/probe'], true)) {
            $response['halt'] = $this->halt;
        }

        return $this->checkHalt($path, $response);
    }

    private function respond(string $path, array $data): array
    {
        if ($path === '/observe') {
            $this->frames[] = (bool) ($data['frame'] ?? false);
            [$network, $this->log] = [$this->log, []];

            return ['network' => $network, 'actor' => 'a', 'page' => ['controls' => []], 'frame' => ! empty($data['frame']) ? base64_encode("\xff\xd8quadro") : null];
        }
        if ($path === '/action' && ($data['kind'] ?? null) === 'goto') {
            $this->gotos[] = (string) $data['path'];

            return ['ok' => true];
        }
        $route = (string) ($data['path'] ?? '');
        if ($path === '/dom_probe') {
            for ($i = 0; $i < $this->navigationCost; $i++) {
                $this->proxied($i === 0 ? $route : '/assets/recurso-'.$i.'.js', 200);
            }
            $token = (string) ($data['token'] ?? '');

            return ['executed' => $this->vulnerable, 'token' => $this->vulnerable ? $token : null];
        }
        if ($path !== '/probe') {
            return ['network' => [], 'actor' => 'a'];
        }
        $inject = $data['inject'] ?? null;
        $value = is_array($inject) ? (string) ($inject['value'] ?? '') : '';
        $this->sent[] = $route.' '.$value;
        if (str_contains($route, 'retorno')) {
            $this->proxied($route, 302, $this->vulnerable ? $value : '/vulneravel/painel');

            return ['sample' => '', 'type' => '', 'status' => 0, 'elapsed' => 30];
        }
        $answer = $this->answer($route, $value);
        $this->proxied($route, $answer['status']);

        return $answer;
    }

    private function proxied(string $route, int $status, ?string $location = null): void
    {
        $this->log[] = ['method' => 'GET', 'host' => 'lab.egide.test', 'path' => explode('?', $route, 2)[0], 'status' => $status,
            'allowed' => true, 'reason' => '', 'issues' => [], ...($location === null ? [] : ['location' => $location])];
    }

    private function answer(string $route, string $value): array
    {
        $safe = ['sample' => 'ok', 'type' => 'application/json', 'status' => 200, 'elapsed' => 50];
        // domXssSweep probes (no inject): entry HTML + bundle with a source-fed sink.
        if ($value === '' && str_contains($route, 'vulneravel') && ! str_contains($route, '.js')) {
            return ['sample' => '<html><script src="/assets/app.js"></script></html>', 'type' => 'text/html', 'status' => 200, 'elapsed' => 40];
        }
        if ($value === '' && str_contains($route, '.js')) {
            $sink = $this->vulnerable ? 'el.dangerouslySetInnerHTML = {__html: h};' : 'el.textContent = h;';

            return ['sample' => 'var h = location.hash.slice(1); '.$sink, 'type' => 'application/javascript', 'status' => 200, 'elapsed' => 40];
        }
        if (str_contains($route, 'perfil')) {
            $shown = $this->vulnerable ? str_replace(['<', '>'], '', $value) : htmlspecialchars($value, ENT_QUOTES);

            return ['sample' => '<input name="apelido" value="'.$shown.'">', 'type' => 'text/html', 'status' => 200, 'elapsed' => 40];
        }
        if (str_contains($route, 'mensagem')) {
            $rendered = $this->vulnerable && preg_match('~\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}~', $value, $factors) ? (string) ($factors[1] * $factors[2]) : $value;

            return ['sample' => '<p>Olá '.htmlspecialchars($rendered).'</p>', 'type' => 'text/html', 'status' => 200, 'elapsed' => 40];
        }
        if (str_contains($route, 'relatorio')) {
            if ($this->vulnerable) {
                return ['sample' => "TypeError: RelatorioController::mes(): Argument #1 must be of type int in /var/www/html/vendor/laravel/framework/src/Illuminate/Routing/ControllerDispatcher.php on line 46\nStack trace:\n#0 /var/www/html/app/Http/Controllers/RelatorioController.php(21): mes()", 'type' => 'text/html', 'status' => 500, 'elapsed' => 40];
            }

            return ['sample' => '{"erro":"parâmetro mes inválido"}', 'type' => 'application/json', 'status' => 422, 'elapsed' => 40];
        }
        if (str_contains($route, 'diagnostico')) {
            if (! $this->vulnerable) {
                return ['sample' => '{"erro":"host inválido"}', 'type' => 'application/json', 'status' => 422, 'elapsed' => 40];
            }
            $output = preg_match('~\$\(\((\d+)\*(\d+)\)\)~', $value, $factors) ? ' '.($factors[1] * $factors[2]) : '';

            return ['sample' => '{"saida":"PING ok'.$output.'"}', 'type' => 'application/json', 'status' => 200, 'elapsed' => str_contains($value, 'sleep') ? 6000 : 40];
        }
        if (str_contains($route, 'pedido')) {
            $found = $value === '1' || ($this->vulnerable && str_contains($value, "'1'='1'"));

            return ['sample' => $found ? '{"pedidos":[{"id":"1","item":"Assinatura anual"}]}' : '{"pedidos":[]}', 'type' => 'application/json', 'status' => 200, 'elapsed' => 40];
        }
        if (str_contains($route, 'login')) {
            return $this->vulnerable ? $safe : ['sample' => 'ok', 'type' => 'application/json', 'status' => 429, 'elapsed' => 30];
        }
        if (! $this->vulnerable) {
            return $safe;
        }
        if ((str_contains($value, '$ne') || str_contains($value, '$gt')) && str_contains($route, 'consulta')) {
            return ['sample' => 'MongoServerError: unknown top level operator: $ne', 'type' => 'application/json', 'status' => 500, 'elapsed' => 50];
        }
        if (str_contains($value, 'egideXSS') && str_contains($route, 'busca')) {
            $reflected = $this->escaping ? htmlspecialchars($value, ENT_QUOTES) : $value;

            return ['sample' => '<div>'.$reflected.'</div>', 'type' => 'text/html', 'status' => 200, 'elapsed' => 50];
        }
        if ((stripos($value, 'sleep') !== false || str_contains($value, 'pg_sleep')) && str_contains($route, 'consulta')) {
            return ['sample' => '', 'type' => 'application/json', 'status' => 200, 'elapsed' => 6000];
        }
        if (str_contains($value, '/api/colaborador/') && str_contains($route, 'integrador')) {
            if (preg_match('~/api/colaborador/([A-Za-z0-9]+)~', $value, $match)) {
                CollaboratorHit::create(['token' => $match[1], 'method' => 'GET', 'source_ip' => '10.0.0.9', 'path' => '/fetch', 'received_at' => now()]);
            }

            return $safe;
        }
        if (in_array($value, ["'", '"', "')", "';"], true) && str_contains($route, 'consulta')) {
            return ['sample' => 'Fatal error: SQLSTATE[42000]: Syntax error or access violation near "\'"', 'type' => 'application/json', 'status' => 500, 'elapsed' => 50];
        }
        if (str_contains($value, 'etc/passwd') && str_contains($route, 'arquivo')) {
            return ['sample' => "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", 'type' => 'text/plain', 'status' => 200, 'elapsed' => 50];
        }
        if (str_contains($route, 'graphql') && str_contains($value, '__schema')) {
            return ['sample' => '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}', 'type' => 'application/json', 'status' => 200, 'elapsed' => 50];
        }

        return $safe;
    }
}
