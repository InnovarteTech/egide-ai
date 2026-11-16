# IA, payloads e oráculos

O motor tem dois papéis: **navegador**, que escolhe controles da interface, e **estrategista**, que escolhe pontos de ataque por endpoint. A configuração global vem de [Engine](../../app/Security/Engine.php), [Platform](../../app/Models/Platform.php) e [AdminController](../../app/Http/Controllers/AdminController.php). [Planner](../../app/Security/Planner.php) encaminha chamadas a provedores hospedados ou CLIs locais disponíveis, exige respostas estruturadas e valida escolhas. O laboratório pode executar roteiro sem IA.

## Da observação ao teste

1. O [SurfaceController](../../app/Http/Controllers/SurfaceController.php) pode importar OpenAPI 3, Swagger 2, Postman ou HAR para o ambiente; [SurfaceImport](../../app/Security/SurfaceImport.php) normaliza rotas e trata as origens conforme o formato. HAR e Postman descartam hosts externos; OpenAPI e Swagger associam as rotas à origem principal, com aviso, quando nenhum servidor do documento corresponde ao ambiente. `RunScan::importSurface()` incorpora essa fonte antes da navegação. O runner fornece observações e tráfego; [EndpointMap](../../app/Security/EndpointMap.php) mescla o inventário e também infere rotas de bundles JS. Uma rota importada ainda precisa passar por escopo e provas para produzir achado.
2. [AgenticRun](../../app/Security/AgenticRun.php) prioriza endpoints e descarta assets, rotas fora de escopo ou destrutivas.
3. `Planner::attackPlan()` une uma linha de base de [AttackPoints](../../app/Security/AttackPoints.php) às sugestões da IA. [Payloads](../../app/Security/Payloads.php) gera cargas para cada ponto.
4. [ProbesInjectionPoints](../../app/Jobs/Concerns/ProbesInjectionPoints.php) e [ProbesApiWrites](../../app/Jobs/Concerns/ProbesApiWrites.php) enviam sondas pelo runner. Os [oráculos de payload](../../app/Security/PayloadOracles.php) e [API](../../app/Security/ApiOracles.php) avaliam respostas e provas antes do achado.
5. A caça adicional em [HuntsAgentically](../../app/Jobs/Concerns/HuntsAgentically.php) usa [Hunter](../../app/Security/Hunter.php): proposta de experimento, validação de técnica/método/rota/carga, execução e veredito. `RunScan` mantém orçamento e estado com [BudgetLedger](../../app/Security/BudgetLedger.php).

## Contrato de prova

A IA não declara vulnerabilidade. Um oráculo confirma, por exemplo, execução DOM observada, erro característico, diferença booleana repetida, atraso medido, marcador de outra conta, callback SSRF ou redirecionamento ao canário. Resposta bloqueada, instável ou insuficiente é `nao_testado`; uma checagem que resistiu pode ser `protegido`. Evidências ficam em `Finding.evidence`, eventos e cobertura. O modelo [Hypothesis](../../app/Models/Hypothesis.php) e sua migração definem estados de hipótese, mas `RunScan` ainda não persiste essas hipóteses. [PayloadOracles](../../app/Security/PayloadOracles.php), [ApiOracles](../../app/Security/ApiOracles.php), [RunScan](../../app/Jobs/RunScan.php).

## Limites e segurança

Os padrões de [config/egide.php](../../config/egide.php) são 12 endpoints, 6 payloads por ponto, profundidade 3, 80 chamadas do estrategista e até 60 passos da caça (20 em demo), todos configuráveis por ambiente. O orçamento total, a reserva de configuração, as cotas por fase de [BudgetLedger](../../app/Security/BudgetLedger.php) e o tempo restante limitam a execução. `Hunter::guard()` rejeita combinações inválidas e cargas perigosas; `Scope::allows()` e [guard.py](../../runner/guard.py) ainda aplicam escopo e segurança no proxy. O README cita outros valores; veja [decisões pendentes](../discovery/2026-11-16-product-architecture-and-docs-plan.md). [AgenticRun](../../app/Security/AgenticRun.php), [Hunter](../../app/Security/Hunter.php), [RunScan](../../app/Jobs/RunScan.php).

## Ao estender

Uma técnica nova precisa de schema/planejamento, carga, envio pelo runner, oráculo, evento/cobertura, evidência e testes do alvo vulnerável **e** corrigido. Testes de referência: [PlannerTest](../../tests/Feature/PlannerTest.php), [AgenticRunTest](../../tests/Feature/AgenticRunTest.php), [AgenticLabTest](../../tests/Feature/AgenticLabTest.php), [PayloadOraclesTest](../../tests/Unit/PayloadOraclesTest.php), [HunterTest](../../tests/Unit/HunterTest.php).
