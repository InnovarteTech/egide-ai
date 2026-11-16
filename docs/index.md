# Mapa técnico da Égide AI

Este índice é a entrada para desenvolvimento. O [README](../README.md) continua sendo a apresentação do produto. A [descoberta do projeto](discovery/2026-11-16-product-architecture-and-docs-plan.md) registra as evidências e as decisões de produto pendentes.

## Primeiro, entenda o fluxo

1. [Arquitetura](architecture.md): fronteiras entre interface, Laravel, fila, runner e Sentinela.
2. [Modelo de dados](data-model.md): entidades, estados e segredos.
3. [Sessões](domains/scans.md): da criação ao relatório.
4. [Escopo e executor](domains/scope-and-runner.md): autorização e controle de tráfego.
5. [Agente e oráculos](domains/agent-and-oracles.md): proposta, execução e prova.

## Depois, escolha o domínio

| Tema | Guia |
| --- | --- |
| Monitoramento contínuo | [Sentinela](domains/sentinel.md) |
| API, CI, agendamento e webhooks | [Integrações](domains/integrations.md) |
| Desenvolvimento local | [Ambiente local](operations/local.md) |
| Deploy e processos | [Produção](operations/production.md) |
| Testes e evidências | [Testes](operations/testing.md) |
| Como alterar um fluxo | [Guia de mudanças](operations/change-guide.md) |

## Como ler estas páginas

Os limites e contratos aqui descritos vêm do código no estado deste PR. Links para arquivos e testes acompanham as regras importantes. Os documentos de [design e planejamento](superpowers/specs/2026-11-09-egide-nucleo-agentico-design.md) registram intenções históricas; confira a implementação antes de usá-los como descrição atual.
