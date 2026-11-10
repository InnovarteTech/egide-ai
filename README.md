# Égide AI

**Segurança garantida, do teste à correção.** A Égide AI faz pentest autônomo e autorizado em aplicações web e APIs: a IA planeja e conduz os ataques, um oráculo determinístico confirma cada falha com evidência reproduzível e um proxy impõe o escopo que o dono autorizou. Depois do teste, o Sentinela vigia logins e acessos suspeitos em produção.

Hack Brasil 2026 · Trilha 06 Cibersegurança

> **A IA propõe. O oráculo prova. O proxy limita.**
> O modelo escolhe onde e como atacar, mas nunca decide sozinho que algo é falha: cada achado precisa de uma prova objetiva (marcador sintético que cruzou contas, script executado no navegador, atraso medido, callback recebido, redirecionamento observado). E nenhuma requisição sai do ambiente isolado sem passar pelas regras de escopo.

## O que a Égide testa

Cada verificação termina em um de três veredictos: **falha** (provada), **protegido** (testado e resistiu) ou **não testado** (não deu para concluir, por exemplo resposta bloqueada ou página instável). A plataforma nunca marca "protegido" quando não conseguiu verificar.

### Autorização e controle de acesso

| Verificação | Referência | Como a falha é provada |
| --- | --- | --- |
| BOLA de leitura entre contas | OWASP API1 · CWE-639 | O marcador sintético da conta B aparece na resposta da conta A |
| BOLA de escrita entre contas | OWASP API1 · CWE-639 | A conta A altera um registro da conta B; o valor original é restaurado |
| IDOR por enumeração de ID | OWASP API1 · CWE-639 | IDs vizinhos devolvem o marcador de outro registro |
| Autorização por função (BFLA) | OWASP API5 · CWE-285 | Conta comum recebe o marcador de uma rota administrativa |
| Acesso sem autenticação | OWASP API2 | A mesma resposta protegida volta sem sessão |
| Atribuição em massa | OWASP API3 | Campo proibido (ex.: `role`) persiste após a escrita; valor restaurado |
| Exposição excessiva de dados | OWASP API3 | A API devolve campo sensível que a tela não mostra |

### Injeção e entrada não confiável

| Verificação | Referência | Como a falha é provada |
| --- | --- | --- |
| XSS refletido | A03 · CWE-79 | Marcador único volta sem escape em resposta HTML |
| XSS no DOM | A03 · CWE-79 | O payload executa script no Firefox e grava um marcador de execução |
| SQLi por tempo | A03 · CWE-89 | Atraso de 4 s ou mais e pelo menos o dobro da linha de base |
| SQLi por erro | A03 · CWE-89 | Assinatura de erro do banco na resposta |
| SQLi booleano | A03 · CWE-89 | Par verdadeiro/falso de mesmo tamanho: a condição verdadeira reproduz a resposta original, a falsa muda; confirmado em duas rodadas, com linha de base estável |
| Injeção NoSQL | A03 · CWE-943 | Erro de banco de documentos na resposta |
| Path traversal | A01 · CWE-22 | Assinatura de `/etc/passwd` ou `win.ini` |
| SSRF | A10 · API7 · CWE-918 | O servidor alvo chama o coletor out-of-band da Égide |
| Redirecionamento aberto | A01 · CWE-601 | O servidor responde 3xx para um domínio-canário `.invalid` (nunca resolve); o host é comparado já interpretado, cobrindo `//`, `/\` e `usuário@host` |

### Autenticação, superfície e configuração

- **JWT fraco:** `alg: none` ou token sem expiração.
- **Limite de tentativas de login:** só é concluído com envio real de credenciais; sonda GET não gera achado.
- **Inventário de API:** rotas alcançáveis que a interface não usa.
- **GraphQL:** introspecção habilitada (OWASP API9).
- **Arquivos sensíveis:** `.env`, `.git/HEAD`, `.git/config`, dumps SQL, `phpinfo`, `server-status`, Spring Actuator e `.DS_Store`.
- **Cabeçalhos e cookies:** HSTS, CSP, proteção contra clickjacking, `nosniff`, versão do servidor exposta e cookies sem `Secure`, `HttpOnly` ou `SameSite`.
- **Regressão:** compara a sessão com a anterior do mesmo ambiente e avisa quando uma falha corrigida volta.

## Como o teste é mantido dentro da autorização

- **Verificação de domínio** por registro DNS TXT em `_egide-verification.<domínio>` ou pelo arquivo `/.well-known/egide-verification.txt` (HTTPS, IP público, sem redirecionamento). A verificação é refeita no início de cada sessão.
- **Proxy de escopo (mitmproxy):** só deixa passar métodos e rotas autorizados, bloqueia rotas negadas, cabeçalhos de sobrescrita de método e travessia de caminho, aplica o orçamento de requisições da sessão (ambiente real: padrão 80, de 10 a 180; laboratório: até 300) e permite no máximo uma rota de escrita de teste com teto de chamadas. Também protege contra DNS rebinding resolvendo e fixando o IP público do alvo.
- **Isolamento de rede:** o Firefox roda com um usuário próprio e regras de `iptables` que só permitem sair pelo proxy.
- **Ambiente de produção vs. teste:** ataques ativos (injeção, escrita, SSRF) só rodam no laboratório ou em ambientes marcados explicitamente como teste. Em produção a Égide só mapeia. Rotas com verbos destrutivos (excluir, cancelar, logout, revogar, redefinir e afins, em português e inglês) nunca são sondadas.
- **Orçamentos do agente:** até 12 endpoints, 6 cargas por ponto, profundidade de escalada 2 e 40 decisões do estrategista por sessão, além do tempo limite do job.
- **Parada de emergência** por sessão e global, pausa da plataforma e suspensão de conta.
- **Segredos:** chave de IA, credenciais de teste e webhooks criptografados no banco; tokens de API e chaves do Sentinela guardados só como hash e exibidos uma única vez. O log do proxy guarda só o host de destino de cada redirecionamento, nunca a query (onde costumam viajar códigos OAuth e tokens de redefinição).
- **A própria plataforma:** em produção, o Apache do contêiner envia Content-Security-Policy restritiva, HSTS, `X-Frame-Options: DENY`, `nosniff`, Referrer-Policy e Permissions-Policy.

## Motor de IA

O motor é único para a plataforma e configurado pelo super admin em **Super admin → Motor de IA**: Anthropic, OpenAI ou OpenRouter por API, ou Claude Code e Codex em linha de comando local (em sandbox, sem ferramentas). São dois papéis: um modelo navegador, rápido, que opera a interface, e um estrategista, que escolhe as classes de ataque por endpoint. Todas as respostas da IA são restritas por JSON Schema. Sem motor configurado, o laboratório roda com roteiro determinístico e o plano de ataque usa só a linha de base por nome de parâmetro.

## Sentinela (monitoramento contínuo)

- **Ingestão:** `POST /api/sentinela/eventos` com a chave do monitor. Tipos aceitos: `login_failed`, `login_succeeded`, `access_denied` e `password_reset`. O identificador do usuário precisa chegar como HMAC-SHA256; e-mail ou nome em texto são recusados pelo servidor.
- **SDK:** pacote para Express em `public/sdk/egide-sentinela.mjs` (em lote, sem bloquear a aplicação). Para Laravel e para qualquer stack via HTTP, a tela do monitor gera o trecho de integração para copiar.
- **Detecção:** força bruta (10 falhas por IP em 5 min), credential stuffing (5 contas por IP em 10 min), suspeita de tomada de conta (login aceito depois de 5 falhas em 15 min), rajada de acessos negados (20 respostas 401/403 por IP em 5 min) e anomalia estatística (falhas acima da média mais três desvios-padrão dos últimos 24 h, em janelas de 5 min).
- **Alertas:** deduplicados por hora e enviados por webhook HTTPS público (Slack, Discord, n8n e similares).

## Automação

- API v1 com tokens (`escapi_…`) para listar ambientes, criar sessões e consultar resultados.
- Portão de CI: a resposta da sessão traz `portao.passou`, que reprova com achado crítico ou alto, com regressão ou com sessão que falhou. Um workflow de exemplo para GitHub Actions fica em `public/ci/egide-github-action.yml`, para o cliente copiar no repositório dele.
- Reteste agendado (diário ou semanal) e aviso por webhook ao fim de cada sessão.

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
| `app/Security` | Escopo e verificação de domínio, planner da IA, pontos de ataque, cargas, oráculos, checagens de configuração e modo demo |
| `app/Jobs` | Orquestração das sessões (`RunScan`) e notificações |
| `app/Sentinel` | Ingestão, detecção e webhooks do Sentinela |
| `runner/` | Executor isolado: servidor de controle, extensão do Firefox, política do proxy e laboratório vulnerável |
| `resources/js/egide` | Interface React |
| `public/sdk`, `public/ci` | SDK do Sentinela e workflow de exemplo do GitHub Actions |
| `tests/` | PHPUnit (`Unit`, `Feature`) e testes do executor em Python (`tests/runner`) |

## Laboratório

O executor sobe um portal de faturas fictício em duas variantes: `vulneravel`, com as falhas plantadas, e `corrigido`, com as mesmas telas protegidas. A demonstração roda a variante vulnerável e o reteste roda a corrigida, provando a correção.

Falhas plantadas: BOLA de leitura e de escrita, BFLA, rota pública, atribuição em massa, exposição excessiva, XSS refletido, XSS no DOM (bundle que escreve `location.hash` em `innerHTML`), SQLi por tempo e booleana (SQLite real em memória), NoSQL (erro de operador), path traversal, SSRF, redirecionamento aberto, introspecção de GraphQL e `.env` exposto. Os arquivos "do sistema" devolvidos pela travessia são sintéticos: o laboratório nunca lê o disco do executor.

Sessões de laboratório e reteste têm orçamento de até 300 requisições, porque o alvo é sintético e a bateria completa precisa disso; ambientes reais continuam limitados a 180. O job tem teto de 14 minutos: as verificações ativas param 3 minutos antes do fim e a varredura de configuração 2 minutos antes, para o relatório sempre fechar com a checagem de arquivos sensíveis.

## Rodar localmente

Requisitos: PHP 8.2+, Composer, Node 22 e Docker.

```bash
cp .env.example .env
bin/egide
```

O script instala as dependências, gera as chaves, roda as migrações, sobe Redis e os executores e inicia o app em http://127.0.0.1:8187.

Para testar um app que roda só na sua máquina, sem expor nada na internet, use `bin/egide-local`.

## Produção

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Variáveis obrigatórias: `APP_KEY`, `APP_URL`, `DB_PASSWORD` e `EGIDE_RUNNER_TOKEN`.

Demonstração pública: `EGIDE_DEMO_ACCESS=true` e o motor de IA configurado no Super admin. Contas de demonstração usam só o laboratório, com cota diária por conta, por IP e global, e são apagadas depois de 24 horas.

## Testes

```bash
php artisan test
python3 -m unittest discover -s tests/runner
```

Os testes PHP cobrem escopo, oráculos, cargas, plano de ataque, o laço agêntico (com o executor simulado), Sentinela, API e demo. Os testes Python cobrem a política do proxy e o laboratório. O caminho completo com Firefox e mitmproxy reais roda pelo laboratório via Docker.

## Limitações conhecidas

- O CVSS exibido é uma estimativa por severidade (9,8 / 7,5 / 5,3 / 3,1), não um cálculo de vetor.
- Os oráculos analisam até 32 KB de cada resposta; comparações de conteúdo exato usam os primeiros 2.000 caracteres e, quando a página é maior, um resultado negativo fica como "não testado".
- BOLA entre contas em sistemas reais exige duas contas de teste cadastradas no ambiente.
- O redirecionamento aberto é detectado pelo cabeçalho `Location`; redirecionamento por JavaScript ou `meta refresh` ainda não é coberto.
- A plataforma ainda não tem cobrança, planos nem times com papéis: cada conta tem o próprio espaço de trabalho.

## Uso responsável

Use a Égide AI somente em sistemas próprios ou com autorização por escrito. A verificação de domínio, o escopo imposto pelo proxy, o isolamento de rede e o orçamento de requisições existem para impedir testes fora do que foi autorizado. O laboratório usa apenas dados fictícios.
