# Sessões, achados e relatórios

Uma sessão é a unidade de trabalho do pentest: recebe escopo e orçamento, percorre o alvo, registra cobertura e produz um resultado. O estado de execução fica em [Scan](../../app/Models/Scan.php); eventos e achados são registros separados. O fluxo completo está em [RunScan](../../app/Jobs/RunScan.php).

## Entradas e modos

| Modo | Como entra | Particularidade |
| --- | --- | --- |
| `laboratory` | Console ou demonstração | Usa variante `vulneravel`; pode usar roteiro sem motor de IA |
| `retest` | Console | Usa variante `corrigido` do laboratório |
| `external` | Console, API v1 ou agenda | Exige ambiente verificado e motor de IA configurado; produção só é mapeada, teste permite bateria agressiva |

O console valida e cria as sessões em [ConsoleController](../../app/Http/Controllers/ConsoleController.php). API e agenda usam [Launcher](../../app/Security/Launcher.php). Todas despacham `RunScan` após a transação. A criação de reteste externo usa `mode=external` com `retest_of`; não confunda com o modo `retest` do laboratório.

## Sequência

1. `RunScan` adquire lock de um runner disponível. Sem runner, reencaminha o job à fila; se a parada já foi solicitada, cancela.
2. Passa `queued → running`, revalida o domínio externo e chama `/start` do runner. A falha de autorização encerra a sessão.
3. No laboratório, prepara contas e executa a bateria sobre a variante escolhida. No externo, mapeia navegação e endpoints; `aggressiveAllowed()` só libera bateria ativa para `lab` ou `env_type=test`.
4. As checagens geram vereditos de cobertura e, quando há prova, `Finding` com evidência. A varredura de configuração roda ao final, com reserva de tempo e requisições.
5. `RunScan` grava resumo, cobertura, estado final e evento; pode comparar achados com sessão anterior e despachar webhook. Em `finally`, para o runner e apaga `engine_key` e `credentials` da sessão.

Fontes: [RunScan](../../app/Jobs/RunScan.php), [Scope](../../app/Security/Scope.php), [NotifyScan](../../app/Jobs/NotifyScan.php).

## Estado, resultado e cobertura

`status` representa execução (`queued`, `running`, `completed`, `failed`, `cancelled`). `phase` é texto de andamento. `result` expressa o desfecho da avaliação, como `mapped`, `exposure`, `protected`, `challenge` ou `inconclusive`. Cobertura por checagem usa `falha`, `protegido` e `nao_testado`. Não interprete `mapped` como comprovação de ausência de falhas. [RunScan](../../app/Jobs/RunScan.php), [Scan](../../app/Models/Scan.php).

## Saídas

O console oferece página de sessão, feed de eventos, imagem atual, imagem de evidência por achado, JSON e página de relatório imprimível. Esses endpoints checam a propriedade da sessão. A API v1 apresenta estado, contagem de achados e `portao`. O portão implementado passa somente quando a sessão está `completed` e não há achados críticos ou altos; a propriedade `regression` não entra hoje nessa expressão. Essa diferença em relação ao README está registrada na [descoberta](../discovery/2026-11-16-product-architecture-and-docs-plan.md). [ConsoleController](../../app/Http/Controllers/ConsoleController.php), [EvidenceController](../../app/Http/Controllers/EvidenceController.php), [ScanApiController](../../app/Http/Controllers/Api/ScanApiController.php).

## Ao estender

Uma nova fase deve atualizar eventos, cobertura e relatório de modo coerente. Um teste inconclusivo permanece `nao_testado`; não crie achado sem evidência. Preserve parada, orçamento, reserva para a varredura final e limpeza de segredos. Testes de referência: [RunScanOraclesTest](../../tests/Feature/RunScanOraclesTest.php), [AgenticLabTest](../../tests/Feature/AgenticLabTest.php), [ScopeGateTest](../../tests/Feature/ScopeGateTest.php).
