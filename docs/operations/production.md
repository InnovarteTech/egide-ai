# Produção e processos

O deploy descrito pelo projeto usa [docker-compose.prod.yml](../../docker-compose.prod.yml). Os serviços são `app`, `horizon`, `scheduler`, PostgreSQL, Redis, Mailpit e três runners. O app e os workers compartilham imagem e storage; runners usam [runner/Dockerfile](../../runner/Dockerfile). O host publica apenas a porta HTTP configurada para o app; runners são internos à rede Compose.

## Configuração e inicialização

Variáveis obrigatórias declaradas no Compose: `APP_KEY`, `APP_URL`, `DB_PASSWORD` e `EGIDE_RUNNER_TOKEN`. O arquivo também permite ajustar porta/bind HTTP, quantidade de workers, cotas de demonstração e conta admin. Revise os valores na [fonte Compose](../../docker-compose.prod.yml), sem copiar segredos para arquivos versionados. O comando documentado no [README](../../README.md) é:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

O [entrypoint](../../docker/entrypoint.sh) prepara diretórios e caches. No papel `app`, executa migrações e, se habilitado, seed do administrador. Horizon processa jobs; scheduler roda comandos periódicos de [routes/console.php](../../routes/console.php). Redis serve à fila; PostgreSQL guarda dados de aplicação.

## Caminho de uma sessão em produção

O app grava a sessão e despacha job. Horizon adquire lock de um dos três URLs de runner. Cada runner é um container com `NET_ADMIN` e Firefox/mitmproxy. O token interno autentica as chamadas do app. O proxy restringe tráfego ao escopo que a sessão enviou. O resultado volta ao banco e o usuário consulta pela interface/API. [RunScan](../../app/Jobs/RunScan.php), [server.py](../../runner/server.py), [policy.py](../../runner/policy.py).

## Operação e observação

- O `app` tem healthcheck HTTP em `/up`; os runners verificam a porta de controle `8791`. [docker-compose.prod.yml](../../docker-compose.prod.yml).
- Pausa global, parada de sessões e suspensão de contas ficam no [AdminController](../../app/Http/Controllers/AdminController.php). O scheduler marca sessões presas como falhas. [routes/console.php](../../routes/console.php).
- O app define cabeçalhos de segurança no [Dockerfile](../../Dockerfile). Mudanças no proxy reverso e HTTPS devem manter `APP_URL`, cookie seguro e cabeçalhos coerentes com o deploy.
- Demonstração pública depende de `EGIDE_DEMO_ACCESS` e de motor de IA disponível; cotas e limpeza de contas temporárias estão em [config/egide.php](../../config/egide.php), [Demo](../../app/Security/Demo.php) e [routes/console.php](../../routes/console.php).

Esta página é um mapa do Compose versionado, não um procedimento de recuperação ou escala testado em um host específico. Para mudanças de deploy, valide o Compose e faça teste no ambiente alvo antes de promover.
