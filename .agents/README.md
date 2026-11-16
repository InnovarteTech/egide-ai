# Skills locais dos agentes

Esta pasta prepara as skills do **Superpowers somente para este checkout**. O Codex encontra skills do projeto em `.agents/skills/`. A instalação local não muda `~/.codex` nem habilita o plugin em outros repositórios.

```text
.agents/
├── README.md                 # este guia, versionado
├── skills/                   # links locais para cada skill, ignorados pelo Git
└── vendor/superpowers/       # cópia do tag v7.0.2, ignorada pelo Git
```

## Preparar

Na raiz do repositório, com Git e acesso ao GitHub:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/install-superpowers.ps1
Test-Path .agents/skills/using-superpowers/SKILL.md
```

Em Linux, macOS ou WSL:

```bash
bash scripts/install-superpowers.sh
test -f .agents/skills/using-superpowers/SKILL.md
```

O teste deve retornar verdadeiro ou terminar com código zero. Abra uma **nova sessão do Codex neste repositório** para carregar as skills. Os scripts fixam o tag `v7.0.2`; não atualizam automaticamente uma cópia já instalada.

Para entender quando usar o fluxo, leia o [guia de refatorações grandes](../docs/operations/superpowers.md). Para as regras próprias da Égide, comece pelo [AGENTS.md](../AGENTS.md) e pelo [índice técnico](../docs/index.md). Os planos em `docs/superpowers/` são documentos históricos e não fazem parte da instalação.
