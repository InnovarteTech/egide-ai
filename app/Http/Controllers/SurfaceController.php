<?php

namespace App\Http\Controllers;

use App\Models\Target;
use App\Models\Workspace;
use App\Security\Scope;
use App\Security\SurfaceImport;
use App\Sentinel\Webhook;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;

class SurfaceController extends Controller
{
    private const LABELS = ['openapi' => 'OpenAPI 3', 'swagger' => 'Swagger 2', 'postman' => 'Postman', 'har' => 'HAR'];

    private const DEMO = 'Na demonstração pública você pode explorar e rodar o laboratório. Para importar a superfície de um ambiente, crie uma conta.';

    public function store(Request $request, Target $target)
    {
        abort_unless($request->user()->id === (int) $target->user_id, 404);
        if ($this->demo($request)) {
            return back()->with('notice', self::DEMO);
        }
        $request->validate([
            'arquivo' => 'nullable|required_without:url|file|max:5120',
            'url' => 'nullable|required_without:arquivo|string|max:2048',
        ], [
            'arquivo.required_without' => 'Envie o arquivo OpenAPI, Swagger, Postman ou HAR, ou informe a URL do documento.',
            'url.required_without' => 'Informe a URL do documento ou envie o arquivo.',
            'arquivo.file' => 'Envie um arquivo válido.',
            'arquivo.max' => 'O arquivo passa do limite de 5 MB.',
        ]);
        $field = $request->hasFile('arquivo') ? 'arquivo' : 'url';
        try {
            if ($field === 'arquivo') {
                $content = (string) file_get_contents($request->file('arquivo')->getRealPath());
                $name = mb_substr(mb_scrub(basename($request->file('arquivo')->getClientOriginalName())), 0, 120);
            } else {
                $content = $this->download($target, (string) $request->input('url'));
                $name = mb_substr(mb_scrub((string) strtok((string) $request->input('url'), '?#')), 0, 250);
            }
            $result = SurfaceImport::parse($content, $name, Scope::origins($target));
        } catch (InvalidArgumentException $error) {
            return back()->withErrors([$field => $error->getMessage()]);
        }
        $meta = $result['meta'];
        if ($meta['count'] === 0) {
            return back()->withErrors([$field => 'Nenhuma rota das origens do ambiente foi encontrada no documento.']);
        }
        $target->mergeCasts(['surface' => 'array', 'surface_meta' => 'array'])->forceFill([
            'surface' => $result['endpoints'],
            'surface_meta' => [...$meta, 'name' => $name, 'via' => $field, 'imported_at' => now()->toIso8601String()],
        ])->save();
        $skipped = $meta['skipped_hosts'] === [] ? '' : ' Endereços fora do ambiente foram ignorados: '.implode(', ', array_slice($meta['skipped_hosts'], 0, 5)).'.';

        return back()->with('notice', 'Superfície importada: '.$meta['count'].' rotas ('.self::LABELS[$meta['format']].').'.$skipped);
    }

    public function destroy(Request $request, Target $target)
    {
        abort_unless($request->user()->id === (int) $target->user_id, 404);
        if ($this->demo($request)) {
            return back()->with('notice', self::DEMO);
        }
        $target->forceFill(['surface' => null, 'surface_meta' => null])->save();

        return back()->with('notice', 'Superfície importada removida.');
    }

    protected function publicAddress(string $url): ?string
    {
        return Webhook::address($url);
    }

    private function download(Target $target, string $url): string
    {
        $parts = parse_url($url);
        $host = is_array($parts) ? strtolower((string) ($parts['host'] ?? '')) : '';
        $hosts = array_map(fn ($origin) => parse_url($origin, PHP_URL_HOST), Scope::origins($target));
        if (! is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['port']) || ! in_array($host, $hosts, true)) {
            throw new InvalidArgumentException('Use um endereço HTTPS de uma das origens do ambiente, sem porta nem credenciais.');
        }
        if ($target->verified_at === null) {
            throw new InvalidArgumentException('Verifique o domínio antes de importar por URL, ou envie o arquivo.');
        }
        if (($address = $this->publicAddress($url)) === null) {
            throw new InvalidArgumentException('O endereço do documento precisa apontar para um IP público.');
        }
        try {
            $response = Http::connectTimeout(5)->timeout(10)->withoutRedirecting()->withOptions(['curl' => [
                CURLOPT_RESOLVE => ["{$host}:443:{$address}"], CURLOPT_MAXFILESIZE => SurfaceImport::MAX_BYTES,
            ]])->get($url);
        } catch (\Throwable) {
            throw new InvalidArgumentException('Não foi possível baixar o documento em até 10 segundos (limite de 5 MB).');
        }
        if (! $response->successful()) {
            throw new InvalidArgumentException('O endereço respondeu HTTP '.$response->status().'. Use a URL final do documento, sem redirecionamento.');
        }
        $body = $response->toPsrResponse()->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }
        $content = Utils::copyToString($body, SurfaceImport::MAX_BYTES + 1);
        if (strlen($content) > SurfaceImport::MAX_BYTES) {
            throw new InvalidArgumentException('O documento passa do limite de 5 MB.');
        }

        return $content;
    }

    private function demo(Request $request): bool
    {
        return Workspace::where('user_id', $request->user()->id)->where('demo', true)->exists();
    }
}
