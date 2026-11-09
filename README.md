# Égide AI

**Segurança garantida, do teste à correção.** Seu time azul com IA: a Égide AI testa aplicações SaaS em domínios verificados, comprova falhas de autorização entre contas (BOLA/IDOR, OWASP API1) com evidência reproduzível, entrega a correção recomendada e confirma o conserto com reteste. Em produção, o Sentinela vigia logins e acessos suspeitos.

Hack Brasil 2026 · Trilha 06 Cibersegurança

## O que faz

- **Avaliação autorizada.** O dono do domínio publica um código em `/.well-known/egide-verification.txt`. Um proxy (mitmproxy) aplica as regras de escopo e o limite de requisições e barra todo o resto, fora do controle da IA.
- **Agente com IA.** O Claude conduz um Firefox isolado com duas contas de teste. A falha só é confirmada quando o marcador sintético de uma conta aparece na resposta da outra, nunca pela opinião do modelo.
- **Relatório.** Resumo executivo gerado só a partir das evidências, achados com referência OWASP/CWE, correção recomendada, trilha de auditoria e reteste com um clique.
- **SaaS multiempresa.** Uma conta por subdomínio, apps React com login por token e modo local sem túnel para testar o app da sua máquina.
- **Sentinela.** SDK para Express e Laravel, identidade do usuário em HMAC, regras de força bruta, credential stuffing, tomada de conta e anomalia contra a linha de base, com alertas por webhook.
- **Automação.** Reteste agendado, API com tokens, workflow para GitHub Actions e aviso de regressão entre sessões.

## Arquitetura

```
Navegador ─▶ Laravel 12 + React/Inertia ─▶ Horizon (Redis) ─▶ RunScan
                                                              │
                        pool de executores (Docker, NET_ADMIN) ◀┘
                        Firefox ESR + extensão observadora + mitmproxy (escopo)

Sentinela SDK ─▶ /api/sentinela/eventos ─▶ detecção (regras + linha de base) ─▶ alertas / webhook
```

| Pasta | Conteúdo |
| --- | --- |
| `app/Security` | Escopo, verificação de domínio, planner da IA, checagens de configuração, modo demo |
| `app/Sentinel` | Ingestão, detecção e webhooks do Sentinela |
| `app/Jobs` | Execução das sessões e notificações |
| `runner/` | Executor isolado: Firefox, extensão observadora, política do proxy e laboratório vulnerável |
| `resources/js/egide` | Interface React (páginas, componentes e layout) |
| `public/sdk`, `public/ci` | SDK do Sentinela e workflow do GitHub Actions |

## Rodar localmente

Requisitos: PHP 8.2+, Composer, Node 22 e Docker.

```bash
cp .env.example .env
bin/egide
```

O script instala as dependências, gera as chaves, roda as migrações, sobe Redis e os executores e inicia o app em http://127.0.0.1:8187.

O motor de IA é único para a plataforma e configurado pelo super admin em **Super admin → Motor de IA** (provedor, modelo, chave criptografada e limite diário de sessões com IA por conta). Sem motor, o laboratório roda com o roteiro determinístico.

## Produção

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Variáveis obrigatórias: `APP_KEY`, `APP_URL`, `DB_PASSWORD` e `EGIDE_RUNNER_TOKEN`.

Demonstração pública: `EGIDE_DEMO_ACCESS=true` e o motor de IA configurado no Super admin. Contas de demonstração usam só o laboratório, com cota diária por conta, por IP e global, e são apagadas depois de 24 horas.

## Testes

```bash
php artisan test
```

## Uso responsável

Use a Égide AI somente em sistemas próprios ou com autorização por escrito. A verificação de domínio, o escopo imposto pelo proxy e o limite de requisições existem para impedir testes fora do que foi autorizado. O laboratório usa apenas dados fictícios.
