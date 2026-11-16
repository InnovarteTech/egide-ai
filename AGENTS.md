# Guia rápido para agentes

Leia [o índice técnico](docs/index.md) antes de alterar um fluxo. O [README](README.md) apresenta o produto ao público; os guias em `docs/` descrevem a implementação atual.

## Roteamento por tarefa

| Se a tarefa envolve | Comece em |
| --- | --- |
| Sessão, relatório, achado ou reteste | [Sessões](docs/domains/scans.md) |
| Alvo autorizado, proxy ou runner | [Escopo e executor](docs/domains/scope-and-runner.md) |
| IA, payload ou oráculo | [Agente e oráculos](docs/domains/agent-and-oracles.md) |
| Monitoramento ou alertas | [Sentinela](docs/domains/sentinel.md) |
| API, CI, agenda ou webhook | [Integrações](docs/domains/integrations.md) |
| Banco, deploy ou ambiente local | [Dados](docs/data-model.md) e [operação](docs/operations/local.md) |

## Antes de editar

1. Siga o fluxo da rota ou job até o efeito final. Leia os testes citados no guia do domínio.
2. Preserve as [invariantes de escopo](docs/domains/scope-and-runner.md), a separação entre proposta da IA e prova do oráculo, e os estados `falha`, `protegido` e `nao_testado`.
3. Para mudanças em `RunScan`, runner ou política do proxy, confira os dois lados do contrato HTTP interno.
4. Atualize a página técnica afetada no mesmo PR. Registre incertezas como tal; não transforme [decisões pendentes](docs/discovery/2026-11-16-product-architecture-and-docs-plan.md#6-questões-de-produto-para-a-revisão) em regras definitivas.

## Verificação

Os comandos e seus pré-requisitos estão em [testes](docs/operations/testing.md). Para PHP: `php artisan test`. Para política e laboratório Python: `python3 -m unittest discover -s tests/runner` no ambiente que possui `mitmproxy`. Execute os testes relevantes à mudança; o fluxo completo de navegador exige Docker.
