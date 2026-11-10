# Núcleo Agêntico da Égide — Plano de Implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transformar o scanner de receita fixa num pentester agêntico — IA (Haiku navega, Sonnet pensa) descobre endpoints, planeja e monta ataques adaptados ao sistema, e os oráculos existentes provam cada achado com evidência reproduzível.

**Architecture:** Loop "IA propõe, oráculo prova, proxy limita". `Planner` roteia chamadas por papel entre dois modelos. Um controlador agêntico substitui a receita fixa de `external()`: recon (Haiku) → inventário de endpoints → plano de ataque por endpoint (Sonnet) → payloads adaptados → execução presa no proxy/escopo/filtro destrutivo → verificação por oráculo determinístico → escalada (Sonnet), tudo limitado por orçamento.

**Tech Stack:** Laravel 12, PHP 8.3, PHPUnit, Pint; executor Python (`runner/server.py`, mitmproxy, Firefox); provedores de IA Anthropic (Haiku/Sonnet) e locais (codex/claude).

**Spec:** `docs/superpowers/specs/2026-11-09-egide-nucleo-agentico-design.md`

## Global Constraints

- Testes agressivos/mutantes **só** com `aggressiveAllowed()` verdadeiro (`scope['lab']` ou `scope['env_type']==='test'`). Fail-closed.
- Todo probe passa por `inScope()`/`Scope::allows` e pelo filtro `destructiveRoute()`.
- Achado só é criado quando um **oráculo determinístico** confirma prova; IA nunca cria finding direto.
- Modelos: navegador `claude-haiku-5-5`, estrategista `claude-sonnet-5-5` (IDs exatos).
- Sem comentários no código e sem commit automático (CLAUDE.md do usuário); commits só quando o executor do plano decidir conforme executing-plans, com autorização já dada para este trabalho.
- `app/Jobs/RunScan.php` já passa de 350 linhas (restrição aceita na Fase 1) — não refatorar o arquivo inteiro; adicionar o loop como colaborador novo onde couber.

## Review Focus

- Modelo navegador ausente na config (provider local/único) → deve cair para o modelo único sem quebrar (Task 1/2).
- IA propõe probe fora de escopo ou em rota destrutiva → precisa ser barrado antes do envio, mesmo vindo do Sonnet (Task 7).
- Resposta da IA fora do schema / provider recusa → loop registra e segue, não derruba a sessão (Task 6/7).
- Loop sem fim ou custo explosivo → tetos de orçamento param a sessão graciosamente (Task 9).
- Falso positivo na variante `corrigido` do lab → oráculo tem de discriminar falha vs protegido (Task 10).

---

### Task 1: Dois modelos na configuração da plataforma

**Files:**
- Create: `database/migrations/2026_11_09_000013_add_nav_model_to_platforms.php`
- Modify: `app/Models/Platform.php`, `app/Security/Engine.php`, `app/Http/Controllers/AdminController.php`
- Test: `tests/Feature/PlatformEngineTest.php`

**Interfaces:**
- Produces: `Engine::platform(bool $external = false): ?array` agora inclui `'nav_model' => string|null` (modelo navegador; null quando não configurado ou provider de modelo único). `Platform` ganha atributo `ai_nav_model` (string, nullable).

- [ ] **Step 1: Teste** em `PlatformEngineTest` — `test_engine_exposes_navigator_and_strategist_models`: configurado anthropic com `ai_model='claude-sonnet-5-5'` e `ai_nav_model='claude-haiku-5-5'`, `Engine::platform()` retorna `model` sonnet e `nav_model` haiku; sem `ai_nav_model`, `nav_model` é null.
- [ ] **Step 2:** rodar — FAIL (coluna/campo inexistente).
- [ ] **Step 3:** migration adiciona `ai_nav_model` string nullable após `ai_model`; `Platform` fillable/casts conforme padrão; `Engine::platform()` inclui `nav_model` (hosted: `$platform->ai_nav_model`; local: null).
- [ ] **Step 4:** rodar — PASS.
- [ ] **Step 5:** teste `test_admin_saves_both_models_and_checks_connection` — admin salva `ai_nav_model`, validação regex igual a `ai_model`, e a verificação de conexão chama o provider com os dois modelos (ou só o estrategista quando nav vazio). Implementar em `AdminController` store + check. PASS.
- [ ] **Step 6:** adicionar o campo "modelo navegador" (`ai_nav_model`) no formulário de motor do super admin (`resources/js/egide/pages/*` da tela de configuração do engine), ao lado do modelo estrategista; opcional (vazio = sem tiering). Sem teste de UI novo — o backend já cobre a validação.
- [ ] **Step 7:** `./vendor/bin/pint` nos arquivos; `php artisan test --filter=PlatformEngine`. Commit.

### Task 2: Planner roteia chamada por papel

**Files:**
- Modify: `app/Security/Planner.php`, `app/Security/Launcher.php`, `app/Http/Controllers/ConsoleController.php`
- Test: `tests/Feature/PentestTest.php`

**Interfaces:**
- Consumes: `Engine::platform()['nav_model']` (Task 1).
- Produces: `Planner::modelFor(Scan $scan, string $role): ?string` (`'navigator'` → `scope['nav_model'] ?? scan->model`; `'strategist'`/qualquer → `scan->model`). `Planner::decide(..., string $role = 'strategist')` usa `modelFor`. `scan->scope['nav_model']` gravado no snapshot de criação pelo Launcher e pelo sessionStore.

- [ ] **Step 1: Teste** `test_planner_routes_navigator_role_to_nav_model`: `Scan` com `model='claude-sonnet-5-5'`, `scope['nav_model']='claude-haiku-5-5'`; `modelFor($scan,'navigator')` === haiku; `modelFor($scan,'strategist')` === sonnet; sem `nav_model`, navigator cai para o model principal.
- [ ] **Step 2:** FAIL (método inexistente).
- [ ] **Step 3:** `modelFor()` em `Planner`; `decide()` aceita `$role` e usa `modelFor` no lugar de `$scan->model` na montagem do payload hosted; `choose()` passa `role='navigator'`. `Launcher::external` e `ConsoleController::sessionStore` gravam `nav_model` no `scope` a partir de `Engine::platform()['nav_model']`.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Pint + `php artisan test --filter=PentestTest`. Commit.

### Task 3: Inventário de endpoints

**Files:**
- Create: `app/Security/EndpointMap.php`
- Modify: `app/Jobs/RunScan.php` (enriquecer captura em `observe()`; novo campo `$inventory`)
- Test: `tests/Feature/EndpointMapTest.php`

**Interfaces:**
- Produces: `EndpointMap::merge(array $current, array $event): array` normaliza e funde um evento de rede observado num inventário cujas chaves são `"METHOD path"` e valores `['method','path','params'=>[],'body'=>[],'auth'=>bool,'seen_in'=>string]`. `EndpointMap::fromBundle(string $js, string $origin): array` extrai rotas candidatas (`/[\w\-/{}.]+` com heurística de API) de um bundle JS.

- [ ] **Step 1: Teste** `test_merge_builds_structured_inventory`: fundir dois eventos (GET `/api/bookings?status=x` e POST `/api/bookings` corpo `{"arena_id":1}`) produz inventário com params `['status']` e body keys `['arena_id']`, dedup por `METHOD path`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** implementar `EndpointMap::merge`.
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Teste** `test_from_bundle_extracts_api_routes`: dado um JS com `fetch("/api/arenas/"+id)` e `axios.post("/api/reservas")`, retorna `/api/arenas/{id}` e `/api/reservas`; ignora assets `.css/.png`. Implementar `fromBundle`. PASS.
- [ ] **Step 6:** em `observe()`, alimentar `$this->inventory` via `EndpointMap::merge` com params (parse do query do path) e body shape (quando o evento trouxer corpo). Teste `test_observe_feeds_inventory` com evento falso injetado. PASS.
- [ ] **Step 7:** Pint + `php artisan test --filter=EndpointMap`. Commit.

### Task 4: Motor de payload

**Files:**
- Create: `app/Security/Payloads.php`
- Test: `tests/Feature/PayloadsTest.php`

**Interfaces:**
- Produces: `Payloads::for(string $class, string $point, array $context = []): array` retorna lista de `['value'=>string,'oracle'=>string,'marker'=>?string]`. Classes: `xss`, `sqli_time`, `sqli_error`, `sqli_bool`, `ssrf`, `traversal`, `open_redirect`. `point`: `query|path|body`. `xss` adapta o breakout ao `context` (`html|attr|js`). `Payloads::marker(string $prefix): string` gera marcador único.

- [ ] **Step 1: Teste** `test_xss_payload_adapts_to_context`: `for('xss','query',['context'=>'attr'])` traz payload com breakout de atributo (`" >`) e marcador único `egideXSS...`; contexto `js` traz breakout de string JS.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** implementar `xss` + `marker`.
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Teste** `test_each_class_yields_payloads_with_oracle`: para cada classe, `for(class,'query')` é não-vazio e cada item nomeia o oráculo verificador (`sqli_time`→`injectionTimeAssess`, `ssrf`→`ssrfAssess`, etc.). Implementar as demais classes. PASS.
- [ ] **Step 6: Teste** `test_sqli_time_payload_is_db_agnostic_sleep`: `sqli_time` inclui variação `SLEEP` e `pg_sleep` (MySQL + Postgres). PASS.
- [ ] **Step 7:** Pint + `php artisan test --filter=Payloads`. Commit.

### Task 5: Runner injeta em path e corpo

**Files:**
- Modify: `runner/server.py` (função `probe`)
- Test: validação via lab (Task 10); sem testes Python no repo.

**Interfaces:**
- Produces: `probe` aceita `inject = {'point':'query'|'path'|'body','key':str,'value':str}`. `path`: substitui o último segmento (ou o segmento `key` quando numérico) pelo `value`, mantendo `resolve_target` (escopo). `body`: envia `value` dentro de um JSON com chave `key`, header `application/json`. `query` permanece como está.

- [ ] **Step 1:** implementar `inject` em `probe`, reusando `resolve_target` para manter o gate de escopo; corpo JSON só com método POST/PUT/PATCH.
- [ ] **Step 2:** sanity local: subir o runner e `curl` um `/probe` com `inject` path e body contra o lab, conferir no log que a requisição saiu com o segmento/corpo certo. (Prova completa na Task 10.)
- [ ] **Step 3:** Commit.

### Task 6: Planejador de ataque (Sonnet)

**Files:**
- Modify: `app/Security/Planner.php`
- Test: `tests/Feature/PentestTest.php`

**Interfaces:**
- Consumes: inventário (Task 3), `decide(...,'strategist')` (Task 2).
- Produces: `Planner::attackPlan(Scan $scan, array $endpoint): array` → `['points'=>[['class'=>..,'point'=>..,'key'=>..], ...]]` via schema forçado. `Planner::baseline(array $endpoint): array` (puro) devolve o conjunto obrigatório: todo param → `xss`+`sqli_time`; path com ID → `idor`; rota de auth → `jwt`+`rate`; param url-like → `ssrf`. `attackPlan` funde baseline + sugestão do Sonnet, dedup.

- [ ] **Step 1: Teste** `test_baseline_covers_params_ids_and_auth`: endpoint `/api/bookings/{id}` com param `status` → baseline inclui `idor` (path id), `xss`+`sqli_time` (param), e para `/auth/login` inclui `rate`+`jwt`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** implementar `baseline` (puro).
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** implementar `attackPlan` (schema + merge com baseline). Teste `test_attack_plan_merges_baseline_even_if_ai_empty`: com um fake de `decide` retornando `{points:[]}`, o plano ainda traz a baseline. (Extrair a fusão para método puro `mergePlan(array $baseline, array $ai)` e testar esse.) PASS.
- [ ] **Step 6:** Pint + `php artisan test --filter=PentestTest`. Commit.

### Task 7: Controlador do loop agêntico

**Files:**
- Create: `app/Security/AgenticRun.php` (colaborador que recebe o `RunScan` e orquestra o loop)
- Modify: `app/Jobs/RunScan.php` (`external()` chama o loop quando `aggressiveAllowed()`, reusando mapExternal para o recon)
- Test: `tests/Feature/PentestTest.php`

**Interfaces:**
- Consumes: inventário (3), `Payloads` (4), runner inject (5), `attackPlan` (6), oráculos existentes (`injectionReflectedAssess`, `injectionTimeAssess`, `ssrfAssess`, `unauthAssess`, `jwtAssess`, `authRateAssess`, BOLA/BFLA), `softCheck`, `inScope`, `destructiveRoute`, `cover`, `callbackToken`.
- Produces: fluxo recon→plano→payload→execute→verifica→escalada. Cada probe: pula se `destructiveRoute` ou fora de `inScope`; envia via runner; resultado passa pelo oráculo nomeado no payload; só cria finding se o oráculo confirmar. Escalada chama `attackPlan` de novo no endpoint do achado, respeitando profundidade.

- [ ] **Step 1: Teste** `test_run_plan_selects_endpoints_within_budget` (puro): dado inventário de N endpoints e orçamento `maxEndpoints=k`, o seletor devolve k. Extrair `AgenticRun::selectTargets(array $inventory, array $budget): array`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** implementar `selectTargets` (prioriza endpoints de API com params/ID sobre assets).
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Teste** `test_probe_blocks_destructive_and_out_of_scope`: `AgenticRun::shouldProbe($route)` falso para `/usuarios/excluir` e para host fora de escopo; verdadeiro para `/api/bookings/12`. Implementar e ligar no loop. PASS.
- [ ] **Step 6:** implementar o loop em `AgenticRun::run()` e chamá-lo de `external()` após o recon quando `aggressiveAllowed()`. Verificação de comportamento fica na Task 10 (lab). PASS nos testes de plumbing.
- [ ] **Step 7:** Pint + `php artisan test`. Commit.

### Task 8: Ligar oráculos mortos (JWT e rate-limit)

**Files:**
- Modify: `app/Security/AgenticRun.php`
- Test: `tests/Feature/PentestTest.php`

**Interfaces:**
- Consumes: `jwtAssess(string $token)`, `authRateAssess(string $path, array $statuses)` (já existem).
- Produces: `AgenticRun` chama `jwtAssess` com token capturado (cookie/Authorization observado) e `authRateAssess` na rota de login, cada um via `softCheck`, criando finding só com veredito `falha`.

- [ ] **Step 1: Teste** `test_jwt_and_rate_checks_are_invoked_when_present`: com um token capturado fake e uma rota de login no inventário, o loop registra cobertura `InventoryCheck · JWT` e `Autenticação · limite`. (Testar via método puro `AgenticRun::authChecks(array $inventory, ?string $token): array` que devolve a lista de checagens a disparar.)
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** implementar `authChecks` + ligação no loop.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Pint + testes. Commit.

### Task 9: Orçamentos do loop

**Files:**
- Modify: `app/Security/AgenticRun.php`, `config/egide.php`
- Test: `tests/Feature/PentestTest.php`

**Interfaces:**
- Produces: `AgenticRun::budget(Scan $scan): array` lê de `config('egide.agentic')` com defaults `max_endpoints=12`, `max_payloads_per_point=6`, `max_escalation_depth=2`, `max_strategist_calls=40`. Contadores internos param o loop ao atingir qualquer teto; `scan->budget` (requests) continua como teto global.

- [ ] **Step 1: Teste** `test_budget_counters_stop_each_dimension`: um contador `AgenticRun::withinBudget(array $spent, array $budget): bool` retorna falso ao exceder qualquer dimensão.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** implementar `budget` + `withinBudget` e aplicar no loop.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Pint + testes. Commit.

### Task 10: Aceite no lab local

**Files:**
- Modify: `runner/lab.py` (garantir endpoints com param em query, path e corpo para exercitar os três pontos)
- Test: `tests/Feature/AgenticLabTest.php` (integração guiada) + execução manual do lab documentada

**Interfaces:**
- Consumes: todo o núcleo (1–9).

- [ ] **Step 1:** revisar `lab.py` variante `vulneravel` para ter: endpoint com param de query refletido (XSS), endpoint com ID no path vulnerável a IDOR, endpoint com corpo JSON vulnerável a mass assignment, endpoint SSRF com param url. Variante `corrigido` com as mesmas rotas protegidas.
- [ ] **Step 2:** subir runner + lab + horizon local; lançar scan de laboratório pelo loop agêntico; conferir no relatório: achados de XSS, IDOR/mass, SSRF **com prova** (marcador/tempo/callback), cobertura preenchida, e nenhum finding na variante `corrigido`.
- [ ] **Step 3:** registrar o resultado (ids de scan, contagem de achados, cobertura) e `php artisan test` completo verde. Commit.
