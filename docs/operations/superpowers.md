# Superpowers em refatorações grandes

[Superpowers](https://github.com/obra/superpowers) reúne skills de descoberta, planejamento, execução, depuração e revisão. Ele organiza **como** o agente trabalha; o [AGENTS.md](../../AGENTS.md) e os [guias da Égide](../index.md) fornecem o contexto do projeto. A instalação abaixo fica **somente neste checkout**. Os arquivos em `docs/superpowers/` são planos históricos, não uma instalação das skills.

## Instalar somente neste projeto

O Codex reconhece skills do projeto em `.agents/skills/`. Os scripts abaixo baixam a versão `v7.0.2` para `.agents/vendor/superpowers/` e criam links locais em `.agents/skills/`. Essas duas pastas são ignoradas pelo Git; nenhuma instalação é feita em `~/.codex` ou `~/.agents`. O [mapa da pasta `.agents`](../../.agents/README.md) explica o que é versionado e o que é gerado. [Referência do Codex para skills de projeto](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills).

No Windows PowerShell, na raiz do repositório:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/install-superpowers.ps1
Test-Path .agents/skills/using-superpowers/SKILL.md
```

Em Linux, macOS ou WSL:

```bash
bash scripts/install-superpowers.sh
test -f .agents/skills/using-superpowers/SKILL.md
```

O teste deve retornar verdadeiro/sucesso. Abra uma **nova sessão neste repositório** para o Codex carregar as skills locais. Os scripts exigem Git e acesso ao GitHub; não instalam PHP, Composer, Node, Docker ou dependências da Égide. Para atualizar a versão, revise o tag nos dois scripts, reinstale a cópia local e verifique as instruções da nova versão. A instalação global pelo menu Plugins não é necessária para este projeto.

## Quando usar

Use o fluxo completo para uma mudança que atravessa vários componentes ou altera um contrato sensível: por exemplo, reestruturar `RunScan`, mudar a comunicação Laravel ↔ runner, alterar a política do proxy, redesenhar os oráculos ou migrar o modelo de dados. Para um ajuste pequeno e localizado, siga o [guia de mudanças](change-guide.md) e os testes relevantes.

## Roteiro para uma refatoração grande na Égide

1. **Descobrir.** Descreva o comportamento desejado e o atual. Siga o pedido pelo [índice](../index.md), pela [arquitetura](../architecture.md) e pelos testes. Liste os contratos que não podem mudar: autorização do alvo, proxy, orçamento, prova dos achados, `nao_testado`, isolamento de usuários e limpeza de segredos.
2. **Projetar.** Use `brainstorming` para fechar objetivo, escopo, estados e critérios de aceite. Registre decisões novas em um design datado; não assuma que os [planos de 09/11](../superpowers/specs/2026-11-09-egide-nucleo-agentico-design.md) descrevem o código atual.
3. **Planejar.** Use `writing-plans` para dividir a mudança em passos verificáveis com arquivos e testes concretos. Defina o que será medido em PHP, Python, frontend e runner Docker. Use branch ou worktree isolado para não misturar trabalho em andamento.
4. **Implementar.** Use `executing-plans` ou o fluxo de execução oferecido pelo plugin. Ao mudar PHP e Python, mantenha as duas pontas do contrato no mesmo passo. Uma nova detecção precisa de resultado vulnerável, corrigido e inconclusivo quando aplicável. [Guia de mudanças](change-guide.md).
5. **Revisar e verificar.** Use as skills de revisão e verificação do plugin. Rode os [testes](testing.md) relevantes e o laboratório Docker quando tocar navegação, proxy ou isolamento real. Registre limitações do ambiente no PR.
6. **Entregar.** Atualize a página técnica afetada, explique migração/risco operacional, compare o resultado com os critérios de aceite e abra ou atualize o PR. Não trate o design como prova de implementação.

As instruções do usuário e as invariantes de segurança do projeto continuam valendo durante qualquer workflow do plugin. Para trabalhos em paralelo, escolha o fluxo apropriado ao escopo e às ferramentas disponíveis; paralelismo não é requisito para usar Superpowers.
