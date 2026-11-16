# Escopo, autorização e executor

O escopo é uma regra executável definida pelo dono do ambiente. [Scope](../../app/Security/Scope.php) normaliza origens e caminhos, valida regras, verifica domínio e constrói o payload de inicialização. O [runner Python](../../runner/server.py) inicia o navegador; [policy.py](../../runner/policy.py) aplica o escopo e as barreiras de [guard.py](../../runner/guard.py) em cada requisição.

## Antes do teste

O ambiente armazena origem HTTPS, origem opcional da API, caminho inicial, regras de método/caminho, caminhos negados, tipo `production` ou `test`, contas de teste opcionais, modo de segurança, escritas aprovadas, limite de requisições por segundo e foco de análise. A prova de domínio aceita TXT em `_egide-verification` ou arquivo `/.well-known/egide-verification.txt`. A verificação do arquivo exige HTTPS, IP público, resposta 200 e ausência de redirecionamento. Ela é refeita por [Launcher](../../app/Security/Launcher.php) ou pelo console antes da sessão, e por [RunScan](../../app/Jobs/RunScan.php) ao executá-la. Alvos locais seguem a exceção explícita de `Scope::localEnabled()`. [ConsoleController](../../app/Http/Controllers/ConsoleController.php), [Scope](../../app/Security/Scope.php).

## Dentro do runner

`RunScan` chama `/start` com URL, regras, negações, orçamento, eventual regra de escrita, `safety`, `approved_writes`, `max_rps` e `session_tag`. `server.py` valida o payload, cria uma sessão isolada, inicia mitmproxy e Firefox com a extensão observadora. O job usa `/observe`, `/action`, `/probe` e outros endpoints internos; todos os POSTs de controle exigem token. O servidor também expõe `/canary` para registrar canários, mas `RunScan` ainda não chama esse endpoint. O [addon.js](../../runner/addon.js) relata controles e atividade de rede. A política do proxy bloqueia destino, método, rota e caminhos inválidos; limita requisições e escritas; fixa IP público do alvo no momento da conexão para reduzir DNS rebinding. [RunScan](../../app/Jobs/RunScan.php), [server.py](../../runner/server.py), [session_extras.py](../../runner/session_extras.py), [policy.py](../../runner/policy.py).

O modo `mapeamento` é imposto para `production`; novos ambientes `test` usam `canario` por padrão ou `livre` quando configurado. A migração deixa ambientes de teste existentes em `livre`. O laboratório usa `lab`. O guard classifica leituras, escritas próprias, escritas irreversíveis e ações com efeito externo; regras de escrita aprovadas podem liberar uma ação classificada como bloqueada nos modos aplicáveis, mas não removem a proibição de PUT/PATCH/DELETE em `mapeamento` nem as regras de escopo e orçamento. Nas sessões externas, o proxy aplica ritmo por `max_rps`, marca a requisição com `X-Egide-Session` e pode pausar a sessão após sinais repetidos de WAF, 429, erros 5xx, falhas de login ou latência alta; o laboratório não aplica esse ritmo nem esses sinais. O runner devolve `halt`; `RunScan` registra a parada, impede novas ações e encerra a sessão como `failed`. Uma nova execução exige outra sessão. [Scope](../../app/Security/Scope.php), [migração](../../database/migrations/2026_11_14_000005_add_safety_to_targets.php), [guard.py](../../runner/guard.py), [policy.py](../../runner/policy.py), [RunScan](../../app/Jobs/RunScan.php).

## Invariantes

- `Scope::allows()` é uma checagem antes de executar; o proxy mantém a barreira final de escopo e segurança. Mudanças em um lado exigem revisão de `server.py`, `policy.py`, `guard.py` e `session_extras.py`.
- Em `production`, `Scope::launch()` não inclui regra de escrita, `RunScan::aggressiveAllowed()` é falso e o runner recebe `mapeamento`. No laboratório ou ambiente `test`, os testes ativos ainda dependem das regras permitidas, do modo de segurança e dos orçamentos.
- Regras negadas prevalecem. Rotas com verbos destrutivos são descartadas pelas checagens agênticas. A política bloqueia sobrescrita de método e travessia de caminho.
- Contas A e B usam perfis separados para provas entre contas. Uma sessão de reteste sem prova suficiente pode terminar `inconclusive`.
- Em modo local, origens `.local.egide.test` e porta explícita são aceitas somente com a configuração local; o proxy encaminha ao host do app local.

Fontes: [Scope](../../app/Security/Scope.php), [RunScan](../../app/Jobs/RunScan.php), [AgenticRun](../../app/Security/AgenticRun.php), [server.py](../../runner/server.py), [policy.py](../../runner/policy.py), [guard.py](../../runner/guard.py).

## Orçamentos implementados

`Scope::budget()` limita o pedido a no mínimo 10 e, por modo, a: laboratório/reteste **600**, externo `production` **180**, externo `test` **2000**. A API v1 aceita pedido até **180**. O proxy recebe o orçamento final no `/start`; há também teto próprio para a regra de escrita. [BudgetLedger](../../app/Security/BudgetLedger.php) distribui o orçamento do job entre observação, prova entre contas, sondas e caça, preservando a reserva de configuração; `RunScan` registra consumo e duração por fase. Esses valores diferem do README e seguem pendentes de decisão de produto. [Scope](../../app/Security/Scope.php), [RunScan](../../app/Jobs/RunScan.php), [ScanApiController](../../app/Http/Controllers/Api/ScanApiController.php), [policy.py](../../runner/policy.py), [descoberta](../discovery/2026-11-16-product-architecture-and-docs-plan.md).

## Ao estender

Para um novo tipo de requisição ou endpoint do runner, revise validação em PHP, payload de `/start`, `server.py`, `session_extras.py`, `policy.py`, `guard.py` e os testes. Nunca abra tráfego externo por conveniência de um teste. Referências: [ScopeTest](../../tests/Unit/ScopeTest.php), [ScopeGateTest](../../tests/Feature/ScopeGateTest.php), [SafetyIntegrationTest](../../tests/Feature/SafetyIntegrationTest.php), [TargetSafetySettingsTest](../../tests/Feature/TargetSafetySettingsTest.php), [test_policy.py](../../tests/runner/test_policy.py), [test_runner_extras.py](../../tests/runner/test_runner_extras.py), [guia de mudanças](../operations/change-guide.md).
