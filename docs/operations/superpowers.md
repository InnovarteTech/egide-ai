# Superpowers em refatorações grandes

[Superpowers](https://github.com/obra/superpowers) é um plugin com skills de descoberta, planejamento, execução, depuração e revisão. Ele organiza **como** o agente trabalha; o [AGENTS.md](../../AGENTS.md) e os [guias da Égide](../index.md) fornecem o contexto do projeto. A instalação é feita no Codex de cada pessoa, não pelo clone deste repositório. Os arquivos em `docs/superpowers/` são planos históricos, não uma instalação do plugin.

## Instalar no Codex

No **Codex App**, abra **Plugins**, procure **Superpowers** na seção de desenvolvimento e instale. No **Codex CLI**, o menu `/plugins` também permite buscar e instalar Superpowers. Essas são as opções descritas pelo [projeto oficial](https://github.com/obra/superpowers#codex-app).

Para instalar diretamente do marketplace do projeto original no Codex CLI, a partir de qualquer pasta:

```text
codex plugin marketplace add obra/superpowers --ref main
codex plugin add superpowers@superpowers-dev
codex plugin list --marketplace superpowers-dev --json
```

O último comando deve mostrar `installed: true` e `enabled: true`. Se o marketplace já estiver cadastrado, pule o primeiro comando. Confira o nome retornado por `codex plugin marketplace list` caso o projeto original mude o identificador `superpowers-dev`. Inicie uma **nova sessão** do Codex após instalar para que as skills sejam carregadas. O plugin não instala PHP, Composer, Node, Docker ou dependências da Égide.

Quem usa **Claude Code** pode instalar o mesmo conjunto de skills separadamente com `/plugin install superpowers@claude-plugins-official`, conforme o [guia oficial](https://github.com/obra/superpowers#claude-code). Uma instalação no Codex não instala o plugin no Claude Code, nem o inverso.

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
