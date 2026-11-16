# Guia de mudanças por cenário

Use este roteiro depois de entender [a arquitetura](../architecture.md) e o domínio afetado. Ele indica caminhos de investigação, não substitui a leitura do fluxo completo.

Se a mudança atravessar vários serviços ou alterar uma barreira de segurança, comece pelo [roteiro de refatoração grande com Superpowers](superpowers.md).

## Nova verificação de segurança

Comece em [agente e oráculos](../domains/agent-and-oracles.md). Identifique se o endpoint veio do tráfego, de bundles JS em [EndpointMap](../../app/Security/EndpointMap.php) ou de documento importado por [SurfaceController](../../app/Http/Controllers/SurfaceController.php) e [SurfaceImport](../../app/Security/SurfaceImport.php). Siga escolha/payload em [Planner](../../app/Security/Planner.php) e [Payloads](../../app/Security/Payloads.php), envio em [RunScan](../../app/Jobs/RunScan.php) ou seus traits, e prova em [PayloadOracles](../../app/Security/PayloadOracles.php) / [ApiOracles](../../app/Security/ApiOracles.php). Acrescente cobertura e evidência, respeite orçamento por fase e escopo, e teste vulnerável, corrigido e inconclusivo. Atualize a página do domínio.

## Novo endpoint ou ação do runner

Siga `RunScan::runner()` até o handler em [runner/server.py](../../runner/server.py). Confirme token, ID de sessão, formato de entrada/saída e parada. Se gerar tráfego ao alvo, revise [Scope](../../app/Security/Scope.php), [session_extras.py](../../runner/session_extras.py), [policy.py](../../runner/policy.py) e [guard.py](../../runner/guard.py), inclusive modo de segurança, escritas aprovadas, ritmo e sinal de parada. Teste o contrato e a política antes de usar o endpoint em uma bateria.

## Nova origem de inventário

Para OpenAPI, Swagger, Postman ou HAR, acompanhe a entrada em [SurfaceController](../../app/Http/Controllers/SurfaceController.php), normalização e tratamento de origens em [SurfaceImport](../../app/Security/SurfaceImport.php), persistência em [Target](../../app/Models/Target.php) e mesclagem em `RunScan::importSurface()`. HAR e Postman descartam hosts externos; OpenAPI e Swagger usam a origem principal com aviso quando nenhum servidor corresponde. Uma rota importada não autoriza tráfego por si só: preserve as regras de [Scope](../../app/Security/Scope.php) e do proxy. Verifique [SurfaceControllerTest](../../tests/Feature/SurfaceControllerTest.php) e [SurfaceImportTest](../../tests/Unit/SurfaceImportTest.php).

## Nova regra de segurança do ambiente

Siga o campo desde [ConsoleController](../../app/Http/Controllers/ConsoleController.php) e [Scope::launch()](../../app/Security/Scope.php) até `RunScan::safety()`, a validação em [session_extras.py](../../runner/session_extras.py) e a decisão por requisição em [policy.py](../../runner/policy.py) / [guard.py](../../runner/guard.py). Preserve `mapeamento` em produção, a aprovação explícita de escritas, a parada automática e o limite de requisições. Verifique [TargetSafetySettingsTest](../../tests/Feature/TargetSafetySettingsTest.php), [SafetyIntegrationTest](../../tests/Feature/SafetyIntegrationTest.php) e [test_policy.py](../../tests/runner/test_policy.py).

## Novo evento ou regra do Sentinela

Atualize o tipo em [MonitorEvent](../../app/Models/MonitorEvent.php), a validação em [Ingest](../../app/Sentinel/Ingest.php), a regra em [Detector](../../app/Sentinel/Detector.php), o [SDK Express](../../public/sdk/egide-sentinela.mjs) se aplicável, e a página em [resources/js/egide/pages/sentinel.jsx](../../resources/js/egide/pages/sentinel.jsx). Preserve identidade em hash, isolamento de monitor, deduplicação e retenção. Verifique [SentinelTest](../../tests/Feature/SentinelTest.php) e atualize [o guia](../domains/sentinel.md).

## Nova tela ou campo de produto

Ache a rota em [routes/web.php](../../routes/web.php), props e validação no controlador, persistência/casts no modelo e na migração, e componente no mapa de [resources/js/egide.jsx](../../resources/js/egide.jsx). Preserve autorização de usuário e restrições da demonstração. Confira o estado vazio, erros de validação e o fluxo correspondente em `tests/Feature`. Atualize [arquitetura](../architecture.md) ou o guia do domínio se a tela mudar o fluxo.

## Mudança de deploy ou configuração

Confira [.env.example](../../.env.example), [config/egide.php](../../config/egide.php), [Compose local](../../compose.yaml), [Compose de produção](../../docker-compose.prod.yml), [Dockerfile](../../Dockerfile) e [entrypoint](../../docker/entrypoint.sh) conforme o caso. Documente diferenças de ambiente em [local](local.md) e [produção](production.md). Não registre valores secretos nem presuma que um limite documentado é igual ao configurado.
