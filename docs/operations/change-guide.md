# Guia de mudanças por cenário

Use este roteiro depois de entender [a arquitetura](../architecture.md) e o domínio afetado. Ele indica caminhos de investigação, não substitui a leitura do fluxo completo.

## Nova verificação de segurança

Comece em [agente e oráculos](../domains/agent-and-oracles.md). Identifique origem do endpoint em [EndpointMap](../../app/Security/EndpointMap.php), escolha/payload em [Planner](../../app/Security/Planner.php) e [Payloads](../../app/Security/Payloads.php), envio em [RunScan](../../app/Jobs/RunScan.php) ou seus traits, e prova em [PayloadOracles](../../app/Security/PayloadOracles.php) / [ApiOracles](../../app/Security/ApiOracles.php). Acrescente cobertura e evidência, respeite orçamento/escopo, e teste vulnerável, corrigido e inconclusivo. Atualize a página do domínio.

## Novo endpoint ou ação do runner

Siga `RunScan::runner()` até o handler em [runner/server.py](../../runner/server.py). Confirme token, ID de sessão, formato de entrada/saída e parada. Se gerar tráfego ao alvo, revise [policy.py](../../runner/policy.py) e [Scope](../../app/Security/Scope.php). Teste o contrato e a política antes de usar o endpoint em uma bateria.

## Novo evento ou regra do Sentinela

Atualize o tipo em [MonitorEvent](../../app/Models/MonitorEvent.php), a validação em [Ingest](../../app/Sentinel/Ingest.php), a regra em [Detector](../../app/Sentinel/Detector.php), o [SDK Express](../../public/sdk/egide-sentinela.mjs) se aplicável, e a página em [resources/js/egide/pages/sentinel.jsx](../../resources/js/egide/pages/sentinel.jsx). Preserve identidade em hash, isolamento de monitor, deduplicação e retenção. Verifique [SentinelTest](../../tests/Feature/SentinelTest.php) e atualize [o guia](../domains/sentinel.md).

## Nova tela ou campo de produto

Ache a rota em [routes/web.php](../../routes/web.php), props e validação no controlador, persistência/casts no modelo e na migração, e componente no mapa de [resources/js/egide.jsx](../../resources/js/egide.jsx). Preserve autorização de usuário e restrições da demonstração. Confira o estado vazio, erros de validação e o fluxo correspondente em `tests/Feature`. Atualize [arquitetura](../architecture.md) ou o guia do domínio se a tela mudar o fluxo.

## Mudança de deploy ou configuração

Confira [.env.example](../../.env.example), [config/egide.php](../../config/egide.php), [Compose local](../../compose.yaml), [Compose de produção](../../docker-compose.prod.yml), [Dockerfile](../../Dockerfile) e [entrypoint](../../docker/entrypoint.sh) conforme o caso. Documente diferenças de ambiente em [local](local.md) e [produção](production.md). Não registre valores secretos nem presuma que um limite documentado é igual ao configurado.
