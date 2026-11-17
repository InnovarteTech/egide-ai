<?php

namespace App\Jobs\Concerns;

use App\Security\ApiOracles;
use App\Security\Scope;
use Throwable;

trait ProbesApiWrites
{
    private function massTest(string $owner, string $recordPath): void
    {
        if (! $this->aggressiveAllowed()) {
            return;
        }
        $this->scan->update(['phase' => 'Atribuição em massa (mass assignment)']);
        $this->runner('/action', ['kind' => 'switch', 'actor' => $owner]);
        $this->observe();
        $before = $this->runner('/fields', ['path' => $recordPath]);
        if (($before['status'] ?? 0) !== 200) {
            $this->cover('Mass assignment · atribuição em massa', $recordPath, 'nao_testado');

            return;
        }
        $present = collect($before['fields'] ?? [])->pluck('key')->all();
        $candidates = array_values(array_unique([
            ...array_values(array_intersect(ApiOracles::SENSITIVE_FIELDS, $present)),
            ...array_slice(ApiOracles::SENSITIVE_FIELDS, 0, 8),
        ]));
        $verdict = 'nao_testado';
        foreach (array_slice($candidates, 0, 8) as $field) {
            if (! $this->budgetAllows(2)) {
                break;
            }
            $result = $this->massField($recordPath, $before, $field);
            $verdict = $result === 'falha' ? 'falha' : ($result === 'protegido' ? 'protegido' : $verdict);
            if ($result === 'falha') {
                break;
            }
        }
        $this->cover('Mass assignment · atribuição em massa', $recordPath, $verdict);
    }

    private function massField(string $recordPath, array $before, string $field): string
    {
        $original = collect($before['fields'] ?? [])->firstWhere('key', $field)['value'] ?? null;
        $sentinel = 'EGIDE-MA-'.strtoupper(bin2hex(random_bytes(5)));
        $write = $this->runner('/write', ['path' => $recordPath, 'field' => $field, 'value' => $sentinel]);
        $after = $this->runner('/fields', ['path' => $recordPath]);
        $assessment = ApiOracles::massAssignmentAssess($recordPath, $field, $sentinel, $write, $after);
        $wroteOk = empty($write['blocked']) && in_array((int) ($write['status'] ?? 0), [200, 201, 202, 204], true);
        $restored = true;
        if ($wroteOk && $assessment['verdict'] !== 'protegido') {
            $restored = $this->restoreField($recordPath, $field, $original);
        }
        if ($assessment['verdict'] !== 'falha') {
            return $assessment['verdict'];
        }
        $assessment['finding']['evidence']['restored'] = $restored;
        $this->scan->findings()->create($assessment['finding']);
        $this->scan->event('finding', 'Campo privilegiado aceito pelo servidor',
            'O servidor persistiu "'.$field.'" enviado fora do formulário em '.$recordPath.'.'.($restored ? '' : ' Atenção: o valor original pode não ter sido restaurado.'),
            $assessment['finding']['evidence']);

        return 'falha';
    }

    private function restoreField(string $recordPath, string $field, ?string $original): bool
    {
        try {
            $this->runner('/write', ['path' => $recordPath, 'field' => $field, 'value' => (string) ($original ?? '')]);
            $back = collect(($this->runner('/fields', ['path' => $recordPath]))['fields'] ?? [])->firstWhere('key', $field)['value'] ?? null;

            return $back === $original || ($original === null && in_array($back, [null, ''], true));
        } catch (Throwable) {
            return false;
        }
    }

    private function excessiveTest(string $owner, string $recordPath): void
    {
        if (! $this->aggressiveAllowed()) {
            return;
        }
        $this->scan->update(['phase' => 'Exposição excessiva de dados']);
        $this->runner('/action', ['kind' => 'switch', 'actor' => $owner]);
        $observation = $this->observe();
        $fields = $this->runner('/fields', ['path' => $recordPath]);
        if (($fields['status'] ?? 0) !== 200 || empty($fields['fields'])) {
            $this->cover('ExcessiveData · exposição excessiva', $recordPath, 'nao_testado');

            return;
        }
        $labels = collect($this->visible($observation['page']))->map(fn ($control) => $control['label'] ?? '')->implode(' ');
        $uiText = ($observation['page']['text'] ?? '').' '.$labels;
        $assessment = $this->excessiveAssess($recordPath, $fields['fields'], $uiText);
        $this->cover('ExcessiveData · exposição excessiva', $recordPath, $assessment['verdict']);
        if ($assessment['finding']) {
            $this->scan->findings()->create($assessment['finding']);
            $this->scan->event('finding', 'Campo sensível só na API', "A API devolveu \"{$assessment['finding']['evidence']['field']}\" que a tela não mostra em {$recordPath}.", $assessment['finding']['evidence']);
        }
    }

    private function excessiveAssess(string $path, array $apiFields, string $uiText): array
    {
        $sensitive = '~(email|mail|cpf|cnpj|phone|telefone|tenant|conta|internal|interno|salario|salary|role|is_admin|admin|senha|password|token|secret|saldo|balance|documento|^doc|endereco|address|ssn)~i';
        foreach ($apiFields as $field) {
            $key = (string) ($field['key'] ?? '');
            $value = (string) ($field['value'] ?? '');
            if ($key === '' || $value === '' || ! preg_match($sensitive, $key)) {
                continue;
            }
            if (stripos($uiText, $value) === false) {
                return ['verdict' => 'falha', 'finding' => [
                    'title' => 'API devolve campo sensível que a tela não mostra', 'severity' => 'medium',
                    'category' => 'ExcessiveData · exposição excessiva',
                    'evidence' => [
                        'method' => 'GET', 'path' => $path, 'field' => $key, 'in_ui' => false,
                        'reference' => 'OWASP API3:2023 · CWE-213',
                    ],
                    'remediation' => 'Devolva na API só os campos que a tela usa; filtre no servidor campos sensíveis em vez de confiar que o cliente os esconde.',
                ]];
            }
        }

        return ['verdict' => 'protegido', 'finding' => null];
    }

    private function graphqlBatchTest(string $path): void
    {
        if (! Scope::allows($this->scan->scope, 'POST', $path) || ! $this->budgetAllows(2)) {
            return;
        }
        $count = 30;
        $probe = $this->runner('/probe', ['path' => $path, 'method' => 'POST', 'direct' => true, 'raw_body' => ['query' => ApiOracles::aliasFlood('faturas', '', $count)], 'markers' => []]);
        $this->observe($this->frameDue());
        $data = json_decode((string) ($probe['sample'] ?? ''), true);
        $executed = is_array($data['data'] ?? null)
            ? count(array_filter(array_keys($data['data']), fn ($key) => preg_match('~^egideAlias\d+$~', (string) $key)))
            : 0;
        $assessment = ApiOracles::graphqlBatchingAssess($path, $count, $executed);
        $this->cover('InventoryCheck · GraphQL batching', $path, $assessment['verdict']);
        if ($assessment['finding']) {
            $this->scan->findings()->create($assessment['finding']);
            $this->scan->event('finding', 'GraphQL executa lote de operações', $executed.' operações rodaram numa requisição só em '.$path.'.', $assessment['finding']['evidence']);
        }
    }

    private function prototypePollutionTest(string $writePath, string $readPath): void
    {
        if (! $this->aggressiveAllowed() || ! $this->inScope($writePath) || ! $this->inScope($readPath) || ! $this->budgetAllows(2)) {
            return;
        }
        $marker = 'egidePP'.bin2hex(random_bytes(4));
        $this->runner('/probe', ['path' => $writePath, 'method' => 'POST', 'raw_body' => ['__proto__' => ['egidePoluido' => $marker]], 'markers' => []]);
        $this->observe(false);
        $probe = $this->runner('/probe', ['path' => $readPath, 'markers' => [$marker]]);
        $this->observe(false);
        $assessment = ApiOracles::prototypePollutionAssess($writePath, $marker, (string) ($probe['sample'] ?? ''));
        $this->cover('InjectionCheck · prototype pollution', $writePath, $assessment['verdict']);
        if ($assessment['finding']) {
            $this->scan->findings()->create($assessment['finding']);
            $this->scan->event('finding', 'Prototype pollution confirmada', 'Propriedade injetada via __proto__ contaminou a resposta de '.$readPath.'.', $assessment['finding']['evidence']);
        }
    }

    private function verbMatrixTest(string $path): void
    {
        if (! $this->aggressiveAllowed()) {
            return;
        }
        foreach (['DELETE', 'PUT', 'PATCH'] as $method) {
            if (! $this->budgetAllows(1) || ! Scope::allows($this->scan->scope, $method, $path)) {
                continue;
            }
            $probe = $this->runner('/probe', ['path' => $path, 'method' => $method, 'anon' => true, 'markers' => []]);
            $this->observe(false);
            $assessment = ApiOracles::unauthorizedWriteAssess($path, $method, (int) ($probe['status'] ?? 0));
            $this->cover('AuthCheck · método de escrita sem sessão', $path, $assessment['verdict']);
            if ($assessment['finding']) {
                $this->scan->findings()->create($assessment['finding']);
                $this->scan->event('finding', 'Escrita sem autenticação aceita', $method.' anônimo aceito em '.$path.'.', $assessment['finding']['evidence']);

                return;
            }
        }
    }

    private function raceTest(string $path): void
    {
        if (! $this->aggressiveAllowed() || ! Scope::allows($this->scan->scope, 'POST', $path) || ! $this->budgetAllows(6)) {
            return;
        }
        $result = $this->runner('/race', ['path' => $path, 'method' => 'POST', 'count' => 5, 'body' => ['token' => 'egideRC'.bin2hex(random_bytes(4))]]);
        $this->observe(false);
        $ok = (int) ($result['ok'] ?? 0);
        $assessment = ApiOracles::raceAssess($path, $ok);
        $this->cover('LogicCheck · race condition (TOCTOU)', $path, $assessment['verdict']);
        if ($assessment['finding']) {
            $this->scan->findings()->create($assessment['finding']);
            $this->scan->event('finding', 'Race condition confirmada', $ok.' de 5 requisições paralelas aceitas em '.$path.'.', $assessment['finding']['evidence']);
        }
    }

    private function writeMatrixBattery(): void
    {
        if (! $this->aggressiveAllowed()) {
            return;
        }
        $this->scan->update(['phase' => 'Escrita sem sessão, concorrência e protótipo']);
        $seen = [];
        $verb = $race = $proto = $xxe = $csrf = 0;
        foreach ($this->inventory as $endpoint) {
            $path = (string) ($endpoint['path'] ?? '');
            if ($path === '' || isset($seen[$path]) || ! $this->inScope($path)) {
                continue;
            }
            $seen[$path] = true;
            if (! $this->budgetAllows(8)) {
                break;
            }
            if ($verb < 10) {
                $this->softCheck('Métodos de escrita sem sessão', fn () => $this->verbMatrixTest($path));
                $verb++;
            }
            if ($this->isAuthPath($path) || $this->destructiveRoute($path) || ! Scope::allows($this->scan->scope, 'POST', $path)) {
                continue;
            }
            if ($proto < 4) {
                $this->softCheck('Prototype pollution', fn () => $this->prototypePollutionTest($path, $path));
                $proto++;
            }
            if ($race < 3) {
                $this->softCheck('Race condition', fn () => $this->raceTest($path));
                $race++;
            }
            if ($xxe < 4) {
                $this->softCheck('XXE (entidade externa)', fn () => $this->xxeTest($path));
                $xxe++;
            }
            // CSRF só em endpoints cujo método descoberto é de escrita — um POST forjado numa página
            // GET (que uma SPA responde 200) não prova nada e gastaria o orçamento à toa.
            if ($csrf < 4 && in_array(strtoupper((string) ($endpoint['method'] ?? 'GET')), ['POST', 'PUT', 'PATCH'], true)) {
                $this->softCheck('CSRF', fn () => $this->csrfTest($path));
                $csrf++;
            }
        }
    }

    private function isAuthPath(string $path): bool
    {
        return (bool) preg_match('~(?:^|[/_.-])(login|logout|signin|signup|sign-in|sign-up|auth|oauth|entrar|sair|senha|password|passwd|token|session|sessao|mfa|otp|2fa)~i', $path);
    }
}
