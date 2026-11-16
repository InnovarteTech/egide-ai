# Escopo, autorização e executor

O escopo é uma regra executável definida pelo dono do ambiente. [Scope](../../app/Security/Scope.php) normaliza origens e caminhos, valida regras, verifica domínio e constrói o payload de inicialização. O [runner Python](../../runner/server.py) inicia o navegador; [policy.py](../../runner/policy.py) aplica o escopo em cada requisição.

## Antes do teste

O ambiente armazena origem HTTPS, origem opcional da API, caminho inicial, regras de método/caminho, caminhos negados, tipo `production` ou `test` e contas de teste opcionais. A prova de domínio aceita TXT em `_egide-verification` ou arquivo `/.well-known/egide-verification.txt`. A verificação do arquivo exige HTTPS, IP público, resposta 200 e ausência de redirecionamento. Ela é refeita por [Launcher](../../app/Security/Launcher.php) ou pelo console antes da sessão, e por [RunScan](../../app/Jobs/RunScan.php) ao executá-la. Alvos locais seguem a exceção explícita de `Scope::localEnabled()`.

## Dentro do runner

`RunScan` chama `/start` com URL, regras, negações, orçamento e eventual regra de escrita. `server.py` valida o payload, cria uma sessão isolada, inicia mitmproxy e Firefox com a extensão observadora. O job usa `/observe`, `/action`, `/probe` e outros endpoints internos; todos os POSTs de controle exigem token. O [addon.js](../../runner/addon.js) relata controles e atividade de rede. A política do proxy bloqueia destino, método, rota e caminhos inválidos; limita requisições e escritas; fixa IP público do alvo no momento da conexão para reduzir DNS rebinding. [server.py](../../runner/server.py), [policy.py](../../runner/policy.py).

## Invariantes

- `Scope::allows()` é uma checagem antes de executar; o proxy mantém a barreira final. Mudanças em um lado exigem revisão do outro.
- Em `production`, `Scope::launch()` não inclui regra de escrita e `RunScan::aggressiveAllowed()` é falso. No laboratório ou ambiente `test`, os testes ativos ainda dependem das regras permitidas e dos orçamentos.
- Regras negadas prevalecem. Rotas com verbos destrutivos são descartadas pelas checagens agênticas. A política bloqueia sobrescrita de método e travessia de caminho.
- Contas A e B usam perfis separados para provas entre contas. Uma sessão de reteste sem prova suficiente pode terminar `inconclusive`.
- Em modo local, origens `.local.egide.test` e porta explícita são aceitas somente com a configuração local; o proxy encaminha ao host do app local.

Fontes: [Scope](../../app/Security/Scope.php), [RunScan](../../app/Jobs/RunScan.php), [AgenticRun](../../app/Security/AgenticRun.php), [server.py](../../runner/server.py), [policy.py](../../runner/policy.py).

## Orçamentos implementados

`Scope::budget()` limita o pedido a no mínimo 10 e, por modo, a: laboratório/reteste **600**, externo `production` **180**, externo `test` **2000**. A API v1 aceita pedido até **180**. O proxy recebe o orçamento final no `/start`; há também teto próprio para a regra de escrita. Esses valores diferem do README e seguem pendentes de decisão de produto. [Scope](../../app/Security/Scope.php), [ScanApiController](../../app/Http/Controllers/Api/ScanApiController.php), [policy.py](../../runner/policy.py), [descoberta](../discovery/2026-11-16-product-architecture-and-docs-plan.md).

## Ao estender

Para um novo tipo de requisição ou endpoint do runner, revise validação em PHP, payload de `/start`, `server.py`, `policy.py` e os testes. Nunca abra tráfego externo por conveniência de um teste. Referências: [ScopeTest](../../tests/Unit/ScopeTest.php), [ScopeGateTest](../../tests/Feature/ScopeGateTest.php), [test_policy.py](../../tests/runner/test_policy.py), [guia de mudanças](../operations/change-guide.md).
