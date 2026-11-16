# Desenvolvimento local

O caminho principal está em [bin/egide](../../bin/egide): prepara `.env`, dependências, chaves, SQLite e assets; sobe Redis e runners Docker; inicia Horizon e Laravel em `http://127.0.0.1:8187`. Exige PHP 8.2+, Composer, Node 22 e Docker. O script usa Bash. [README](../../README.md), [compose.yaml](../../compose.yaml).

## Início rápido

Em Linux/macOS ou WSL com as ferramentas acessíveis:

```bash
cp .env.example .env
bin/egide
```

No Windows, abra **Git Bash** ou WSL na raiz do repositório e rode `bash bin/egide`. PHP, Composer, Node, npm e Docker precisam estar no `PATH` desse shell. PowerShell sozinho não executa o script Bash. A primeira execução instala dependências e constrói as imagens; pode demorar. O script gera `APP_KEY` e `EGIDE_RUNNER_TOKEN` se faltarem. [bin/egide](../../bin/egide).

`compose.yaml` sobe Redis na porta local `6387`, Mailpit e três runners nas portas locais `8791`, `8793` e `8794`. O Laravel e Horizon rodam no host. O `.env.example` configura SQLite e a lista de runners; confira as portas antes de mudar a topologia. [compose.yaml](../../compose.yaml), [.env.example](../../.env.example), [config/egide.php](../../config/egide.php).

## Alvo local

[bin/egide-local](../../bin/egide-local) é um gateway Python para avaliar um app da máquina. Ele aceita `--porta`, roteamento opcional `--rota` e substituição `--substituir`. A opção `--sem-tunel` evita abrir túnel HTTPS. O cadastro do ambiente local exige `EGIDE_LOCAL_TARGETS=true` e o runner local exige `EGIDE_RUNNER_LOCAL=1`; confira [Scope](../../app/Security/Scope.php) e [server.py](../../runner/server.py) antes de usar. Esse modo é separado da verificação de domínios públicos.

## Onde olhar quando algo falha

| Sintoma | Primeiro lugar |
| --- | --- |
| Sessão continua na fila | Horizon, Redis, `EGIDE_RUNNER_URLS` e lock dos runners em [RunScan](../../app/Jobs/RunScan.php) |
| Runner não responde | Containers `browser`, `browser-2`, `browser-3`, token compartilhado e `/health` do [server.py](../../runner/server.py) |
| Domínio recusado | Regras e prova em [Scope](../../app/Security/Scope.php) e política em [policy.py](../../runner/policy.py) |
| Interface sem assets | `npm run build` e [vite.config.js](../../vite.config.js) |

Para verificações reproduzíveis, veja [testes](testing.md). Nunca copie `.env` ou credenciais reais para documentação ou PR.
