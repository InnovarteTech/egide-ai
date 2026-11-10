# Núcleo Agêntico da Égide — Documento de Design

**Data:** 2026-11-09
**Autor:** Jeová + Claude (Opus 4.8)
**Status:** aprovado para planejamento

## 1. Intenção e o porquê

Hoje o scanner da Égide é um **executor de receitas fixas**: a IA (`Planner`) só
navega e clica; os oráculos atacam seguindo um roteiro rígido. Isso tem duas
consequências ruins, já observadas em produção contra o API Arena:

- **Não adapta ao sistema.** A injeção só procura query string (`?x=`), então
  uma API REST com ID no caminho (`/api/bookings/12`) não tem onde ser testada.
- **Não é criativo.** A IA nunca decide o que testar, nunca monta payload, nunca
  encadeia achados. Dois oráculos (JWT, rate-limit de login) existem e têm teste,
  mas **nunca são chamados no fluxo** — código morto.

O objetivo deste núcleo é transformar o scanner num **pentester agêntico
criativo**: ele explora a plataforma como um humano, entende os endpoints pelo
front-end, decide o que faz sentido testar naquele sistema específico, monta os
payloads adaptados, e **encontra falhas de verdade** — sem perder a prova
reproduzível, a segurança de escopo e a ausência de alucinação que já são
princípios do produto.

## 2. O princípio que rege tudo

> **A IA propõe. O oráculo prova. O proxy limita.**

- **Criatividade solta na ideação:** a IA descobre endpoints, levanta hipóteses,
  escolhe vetores e monta payloads adaptados ao sistema. Nada engessado.
- **Disciplina no claim:** um achado só vira *finding* quando um **oráculo
  determinístico confirma prova reproduzível** (marcador refletido sem escape,
  delta de tempo mensurável, callback out-of-band recebido, marcador sintético
  cruzado entre contas). A IA **nunca** declara vulnerabilidade sozinha.
- **Segurança no execute:** todo probe passa pelo **mitmproxy (escopo)**, pelo
  **filtro de rota destrutiva** e pelo **gate de ambiente de teste**. A
  criatividade da IA não consegue sair dos limites nem agir fora de um ambiente
  marcado como teste/homologação.

Esse princípio resolve a tensão entre "criativo" e "reproduzível": a segurança
não vem de limitar a imaginação da IA, vem da fronteira do proxy e do verificador.

## 3. Tiering de modelo (dois modelos por sessão)

| Papel | Modelo | Uso | Volume |
|---|---|---|---|
| **Navegador ("braço")** | `claude-haiku-5-5` | Navegar, clicar, preencher, extrair texto, achar formulários/links/XHR, ler resposta para sinais simples | Alto |
| **Estrategista ("cabeça")** | `claude-sonnet-5-5` | Endpoint → classes de ataque; montar/adaptar payload; interpretar resposta ambígua; decidir escalada e encadeamento | Baixo |

Hoje cada scan usa **um** modelo (`scan.engine_key`/`scan.model`). O núcleo troca
isso por **dois modelos por scan**, e o `Planner` roteia cada chamada ao modelo
certo pelo tipo de tarefa. Custo cai porque o modelo caro só é chamado onde
realmente pensa.

## 4. O loop agêntico (substitui a receita fixa de `external()`)

```
1. RECON        (Haiku)   navega o front + coleta XHR observados + lê bundles JS
                          + detecta OpenAPI/Swagger → inventário de endpoints
2. PLANO        (Sonnet)  por endpoint: escolhe classes de ataque candidatas
                          + conjunto base obrigatório → plano de ataque estruturado
3. PAYLOAD      (Sonnet+  monta payload adaptado ao ponto de injeção
                 lib)     (query / path param / corpo JSON) e ao contexto
4. EXECUTE      (runner)  envia o probe — PRESO no proxy (escopo) + filtro
                          destrutivo + gate de ambiente de teste
5. VERIFICA     (oráculo) confirma prova reproduzível → finding; senão nao_testado
6. ESCALADA     (Sonnet)  em achado confirmado, decide o próximo probe/encadeamento
                          dentro do escopo e do orçamento
7. RELATÓRIO    (existe)  resumo executivo + CVSS + portão CI + cobertura
```

O loop é **limitado por orçamento** (ver §7). Os oráculos atuais viram a **camada
de verificação** — são reusados como juízes de prova, não jogados fora.

### Inventário de endpoints (saída do passo 1)

Estrutura por endpoint descoberto:

```
{ method, path, params[], body_shape{}, auth (bool), seen_in ('ui'|'xhr'|'bundle'|'openapi') }
```

O passo 1 descobre a superfície real da API, não só o que está linkado na UI.
Fontes: requisições XHR observadas no proxy durante a navegação do Haiku;
strings de rota nos bundles JS do front; documento OpenAPI/Swagger se existir e
estiver no escopo.

## 5. Classes de vulnerabilidade

### v1 (este núcleo — "core principal 100%")

- **Injeção** em **query, path param E corpo JSON**:
  - XSS refletido sensível a contexto (HTML, atributo, JS)
  - SQLi por tempo, por erro e booleano
- **BOLA / IDOR** (requer 2 contas): acesso a objeto de outra conta + enumeração de ID
- **BFLA** (requer papéis): rota privilegiada acessada por conta comum
- **Mass assignment** com **descoberta de campo** (diff de resposta → campo
  escondido → tenta setar campo de privilégio)
- **Exposição excessiva de dados**
- **SSRF** out-of-band (query + corpo)
- **Acesso sem autenticação**
- **JWT fraco** (wire do oráculo existente)
- **Rate-limit de login** (wire do oráculo existente)
- **Arquivos sensíveis / config / headers** (já existe)
- **Path traversal** e **open redirect** (extras baratos de payload)

### Onda 2 (fora deste núcleo)

GraphQL (introspection + BOLA/injeção sobre GraphQL), lógica de negócio
(preço/quantidade/race), SSTI, command injection, NoSQL injection, encadeamento
avançado multi-passo entre achados.

## 6. Mudanças de dados e configuração

- **Platform**: novo campo `ai_nav_model` (modelo navegador). O `ai_model`
  existente passa a ser o estrategista. Migration.
- **Engine::platform()**: retorna os dois modelos (`model` estrategista +
  `nav_model` navegador) além de provider/key.
- **Scan**: o `scope` (ou colunas) carrega os dois modelos no snapshot de criação,
  igual hoje faz com `model`.
- **Admin UI** (`AdminController` + tela do painel): dois campos de modelo
  (navegador e estrategista). Verificação de conexão testa os dois.
- Provider `lab`/local continua funcionando: quando não há dois modelos (ex.: lab
  determinístico ou provider local de modelo único), o roteamento cai para o
  modelo único disponível — tiering é melhoria, não pré-requisito.

## 7. Orçamento e parada (fail-safe)

O loop precisa de limites rígidos para não girar nem estourar custo:

- **Máx. endpoints** testados por sessão.
- **Máx. payloads por endpoint** (por classe).
- **Profundidade máx. de escalada/encadeamento.**
- **Máx. chamadas ao Sonnet** por sessão (teto de custo da "cabeça").
- **Orçamento de requests** (`scan.budget`, já existe) continua valendo como teto
  global duro.

Atingir qualquer teto encerra graciosamente e registra cobertura parcial. O
`checkStop`/`stop_requested_at` existente continua abortando a sessão a qualquer
momento.

## 8. Segurança (mantida e reforçada)

Nenhuma dessas trava muda — são preservadas pelo design:

- Testes agressivos/mutantes **só** em ambiente marcado `test`/homologação ou no
  lab. Gate fail-closed (`aggressiveAllowed`).
- Todo probe passa pelo **mitmproxy** (escopo de origem/rota).
- **Filtro de rota destrutiva** (incluindo verbos pt-BR) aplicado a TODO probe,
  inclusive os propostos criativamente pela IA.
- Achado só com **prova reproduzível** de oráculo. Sem vuln declarada por IA.
- Evidência de cada finding guarda a requisição/prova exata, como hoje.

## 9. Objetivos, não-objetivos, anti-objetivos

**Objetivos**
- Exploração agêntica que adapta ao sistema e acha falhas reais.
- Dois modelos por tarefa (custo controlado).
- Prova reproduzível em todo finding.

**Não-objetivos**
- Não é fuzzer de escala nem ferramenta de DoS.
- Não "explora além da prova" — prova a falha, não abre shell nem exfiltra dados.
- Não age em produção sem a marca de ambiente de teste.

**Anti-objetivos (falha mesmo se "funcionar")**
- Finding declarado pela IA sem oráculo → **proibido**.
- Loop sem teto de custo/tempo → **proibido**.
- Qualquer escape de escopo ou ação destrutiva → **proibido**.

## 10. Critério de aceite (teste no lab local)

O núcleo está pronto quando, rodando o **loop agêntico** (não a receita antiga)
contra o lab determinístico local (`lab.py`, variante `vulneravel`), ele:

1. Descobre a superfície de endpoints do lab via navegação + XHR.
2. Planeja e dispara ataques adaptados (não roteiro fixo).
3. **Encontra as falhas plantadas** (BOLA, injeção, SSRF, mass assignment,
   exposição) com prova reproduzível.
4. Na variante `corrigido`, reporta `protegido`/`nao_testado` (sem falso
   positivo).
5. Respeita todos os tetos de orçamento e o escopo do proxy.

Depois do lab local verde, Jeová roda em produção contra o Arena marcado como
ambiente de teste.

## 11. O que fica a cargo do builder (plano decide)

- Engenharia de prompt exata do planner/crafter Sonnet (schemas de saída).
- Conteúdo da biblioteca de payloads por classe e por contexto.
- Forma exata do inventário de endpoints e como o parsing de bundle JS extrai rotas.
- Números dos tetos de orçamento do loop.
- Como o roteamento de modelo é injetado no `Planner.decide()` (parâmetro de papel).
