# Égide AI — landing editorial

**Status:** direção A escolhida para a landing; B permanece apenas como estudo histórico. A URL final da agenda continua pendente.

## Intenção

Apresentar a Égide AI a CTOs e líderes de produto que lançam rotas e funcionalidades mais rápido do que conseguem revisar suas fronteiras de acesso. A página deve tornar o risco concreto, mostrar como a Égide produz evidência verificável e levar o visitante a uma conversa com um consultor.

O microsite será público e separado do aplicativo. O inglês será a língua principal, com versão em português brasileiro e estrutura para acrescentar outros idiomas. O destino definitivo do agendamento ainda não existe; o convite terá um estado explícito de “booking opens soon”, sem simular uma reserva.

## Abordagens consideradas

- **Página de produto no aplicativo:** reaproveitaria componentes, mas manteria a landing presa à navegação e à escala visual do console. A decisão anterior foi criar um microsite separado.
- **Campanha cinematográfica feita só de imagens:** teria impacto, mas esconderia a prova que diferencia a Égide e poderia sugerir capacidades ainda não demonstradas.
- **A — editorial escuro com evidência interativa:** usa a escala tipográfica e o respiro da [home da Dovetail](https://dovetail.com/) como referência de composição, com a marca, a história e a ilustração próprias da Égide. Uma escultura de rotas ocupa a primeira dobra; cenas posteriores alternam imagem, silêncio e um artefato legível de prova.
- **B — escudo grego:** usa o escudo como objeto central da marca, em uma composição dividida entre ameixa escuro e pedra clara. O bronze e um percurso violeta sugerem uma fronteira exposta; a prova continua sendo um componente técnico legível. Foi explorada como alternativa e não será usada na landing ativa.

## Verdade do produto

A IA propõe testes; o oráculo determinístico confirma achados; o proxy impõe o escopo autorizado. Em produção, as sessões mapeiam a superfície e verificam configuração. Testes ativos exigem laboratório ou ambiente de teste aprovado. Cada verificação pode terminar como `falha`, `protegido` ou `nao_testado`; falta de prova não vira segurança confirmada. O Sentinela recebe eventos da aplicação, detecta padrões suspeitos e envia alertas; não bloqueia ataques.

A landing não exibirá clientes, notas, métricas, depoimentos, certificações ou resultados reais sem fonte. Os artefatos visuais explicam **como uma falha é confirmada**, em condições hipotéticas ("se a conta A recebe o marcador da conta B..."); não apresentam uma ocorrência de cliente como fato. A página não precisa repetir rótulos como “illustrative”, “synthetic lab” ou “no customer data” sobre cada cena. O limite operacional aparece uma vez, em linguagem clara, junto ao método.

## Percurso e texto

| Cena | Texto principal em inglês | Português brasileiro | O que se vê |
| --- | --- | --- | --- |
| Abertura | **Your product scaled. Your security didn’t.** | **Seu produto escalou. Sua segurança, não.** | Superfícies de produto se multiplicam; uma fronteira de acesso fica exposta. |
| Dor | **A new route. A new way through.** | **Uma nova rota. Um novo caminho.** | Uma requisição da conta A tenta alcançar o recurso da conta B; a cena formula o risco como hipótese. |
| Prova | **Proof, not a guess.** | **Prova, não suposição.** | Requisição, resposta e condição de confirmação em um único quadro reto e legível, em HTML. |
| Amplitude do risco | **The risk doesn't stop at IDOR.** | **O risco vai além do IDOR.** | Nuvem tipográfica central de classes CWE com contraste forte de escala; cinco CVEs reais ocupam os espaços entre as palavras. |
| Método | **Test what you authorize. See what holds.** | **Teste o que você autoriza. Veja o que resiste.** | Um fluxo visual mostra escopo, proposta da IA, checagem do oráculo e resultado. |
| Continuidade | **The next release changes the picture.** | **A próxima versão muda o cenário.** | Um evento de acesso negado recebido pelo Sentinela leva à detecção e ao alerta. |
| Fecho | **Know where to start. Talk to a consultant.** | **Saiba por onde começar. Fale com um consultor.** | Convite claro; o aviso sobre a agenda aparece ao clicar no CTA. |

O texto de apoio será mínimo. Na cena do método, uma frase curta esclarece que testes ativos ocorrem no laboratório ou em ambientes de teste aprovados, enquanto produção recebe mapeamento e checagens de configuração. Rótulos técnicos do artefato serão explícitos e traduzidos.

## Mural de falhas e CVEs

Depois da prova de IDOR, somente a direção A recebe a cena tipográfica **The risk doesn't stop at IDOR.** / **O risco vai além do IDOR.** Vinte e sete classes de falha formam uma nuvem oval concentrada no centro. XSS domina; SQL injection vem em segundo tamanho, seguido de poucas palavras médias e uma cauda bem menor. A escala não linear aumenta o contraste sem alterar a ordem derivada dos registros públicos. Uma moldura reta de 1 px contém a nuvem, com aproximadamente 64 px de respiro nas laterais e pelo menos 40 px entre qualquer termo e a borda. Em desktop, o posicionamento mede as palavras e evita colisões em EN e PT; em telas estreitas, os termos se recompõem em linhas centradas e legíveis. Cinco links `CVE-AAAA-NNNN` verificados no NVD aparecem como microtermos nos vazios do mapa, sem sublinhado e com foco de teclado visível.

O tamanho reflete a quantidade **acumulada** de registros CVE públicos associados ao respectivo CWE no NVD em 17/11/2026, não uma estimativa da frequência em produtos de clientes nem um placar da cobertura da Égide. A cena mostra apenas o link “NVD source ↗” dentro da moldura, também sem sublinhado. A data, o critério de escala e o limite de escopo ficam documentados aqui; o limite operacional aparece na seção de método da landing. Cada palavra mantém CWE e contagem em seu nome acessível e dica de ferramenta. O mural é um recorte verificável, não um catálogo de todas as falhas existentes. Categorias amplas e específicas podem se sobrepor, portanto suas contagens não devem ser somadas. As contagens podem mudar quando o NVD recebe novos registros ou revisa o CWE de um CVE.

| Classe no mural | CWE consultado | CVEs mapeados no NVD em 17/11/2026 | CVE público para anotação |
| --- | --- | ---: | --- |
| XSS | [CWE-79](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-79&resultsPerPage=1) | 25.322 | [CVE-2024-11846](https://nvd.nist.gov/vuln/detail/CVE-2024-11846) |
| SQL injection | [CWE-89](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-89&resultsPerPage=1) | 11.945 | [CVE-2023-34362](https://nvd.nist.gov/vuln/detail/CVE-2023-34362) |
| Path traversal | [CWE-22](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-22&resultsPerPage=1) | 6.532 | [CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773) |
| CSRF | [CWE-352](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-352&resultsPerPage=1) | 4.774 | [CVE-2024-13244](https://nvd.nist.gov/vuln/detail/CVE-2024-13244) |
| Command injection | [CWE-78](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-78&resultsPerPage=1) | 4.036 | — |
| Improper authentication | [CWE-287](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-287&resultsPerPage=1) | 3.117 | — |
| SSRF | [CWE-918](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-918&resultsPerPage=1) | 1.555 | [CVE-2021-26855](https://nvd.nist.gov/vuln/detail/CVE-2021-26855) |
| Hard-coded credentials | [CWE-798](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-798&resultsPerPage=1) | 1.331 | — |
| XXE | [CWE-611](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-611&resultsPerPage=1) | 1.008 | — |
| Open redirect | [CWE-601](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-601&resultsPerPage=1) | 922 | — |
| IDOR (recorte de BOLA) | [CWE-639](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-639&resultsPerPage=1) | 865 | [CVE-2024-42169](https://nvd.nist.gov/vuln/detail/CVE-2024-42169) |
| Input validation | [CWE-20](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-20&resultsPerPage=1) | 9.014 | — |
| Information exposure | [CWE-200](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-200&resultsPerPage=1) | 6.677 | — |
| Code injection | [CWE-94](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-94&resultsPerPage=1) | 3.563 | — |
| Missing authorization | [CWE-862](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-862&resultsPerPage=1) | 3.546 | — |
| Incorrect authorization | [CWE-863](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-863&resultsPerPage=1) | 2.907 | — |
| Unsafe file upload | [CWE-434](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-434&resultsPerPage=1) | 2.169 | — |
| Missing authentication | [CWE-306](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-306&resultsPerPage=1) | 1.963 | — |
| Privilege management | [CWE-269](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-269&resultsPerPage=1) | 1.441 | — |
| Unsafe deserialization | [CWE-502](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-502&resultsPerPage=1) | 1.344 | — |
| File permissions | [CWE-732](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-732&resultsPerPage=1) | 1.248 | — |
| Resource exhaustion | [CWE-400](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-400&resultsPerPage=1) | 1.199 | — |
| Exposed credentials | [CWE-522](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-522&resultsPerPage=1) | 1.037 | — |
| Access control | [CWE-284](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-284&resultsPerPage=1) | 972 | — |
| Sensitive logs | [CWE-532](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-532&resultsPerPage=1) | 768 | — |
| Prototype pollution | [CWE-1321](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-1321&resultsPerPage=1) | 383 | — |
| HTTP request smuggling | [CWE-444](https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-444&resultsPerPage=1) | 223 | — |

“Social engineering” e “scam” são vetores de ameaça, não classes de vulnerabilidade de software com frequência CVE comparável; por decisão editorial, não aparecem no mapa. Também foram retiradas da cena as duas frases sobre o tamanho das palavras e o escopo autorizado. A página continua a explicar os limites do teste na seção de método e não promete testar automaticamente todos os termos do mural.

Na superfície pública, evitar números de categoria OWASP sem edição: [Broken Access Control, Top 10:2025](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/), [Injection, Top 10:2025](https://top10.owasp.org/2025/A05_2025-Injection/), [API1:2023 Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/) e [API7:2023 SSRF](https://api-security.owasp.org/editions/2023/en/0xa7-server-side-request-forgery/). Para a escala, preferir a contagem de CVEs por CWE com período explícito, conforme a [metodologia da CWE Top 25 de 2025](https://cwe.mitre.org/top25/archive/2025/2025_methodology.html); o score geral desse ranking combina frequência e severidade e não deve ser exibido como frequência pura.

## Primeira dobra

O logo real aparece no canto superior esquerdo. Navegação curta, seletor EN/PT-BR e CTA ficam discretos no topo. Na A, uma linha pequena ocupa o alto e o título em Manrope avança até a área central, encontrando visualmente a escultura de rotas; evitar o vazio entre texto e objeto que apareceu na prévia anterior. A primeira dobra comunica risco e ação em poucos segundos, sem cartões, enumeração visível ou subtítulo longo.

Em desktop, a primeira cena precisa caber inteira na altura visível, incluindo cabeçalho, título, arte e convite para avançar. Cada cena posterior também deve caber individualmente em uma tela, sem cortar texto ou o objeto central. Verificar pelo menos 1907 × 850, 1440 × 900 e 1536 × 680; usar escala tipográfica e espaçamento que respondam à altura, além da largura. No mobile, preservar a leitura e permitir fluxo vertical natural.

No mobile, as duas frases continuam grandes e legíveis, mas o objeto visual ganha uma faixa própria entre elas. Nenhuma letra essencial fica sob a ilustração.

## Sistema visual e movimento

Reaproveitar `public/egide.svg`, o wordmark “Égide AI”, Manrope Variable para display, Inter Variable para corpo e mono somente em evidências/rótulos. Partir do roxo `#6435ea`, do azulejo do logo `#5B2EE0`, do ameixa escuro já presente no app (`#23153c` e `#261940`) e do branco suave `#f7f7fc`. Verde, vermelho e neutro conservam o sentido dos estados do produto. Não usar o Orbit atual como imagem central.

A ilustração hero e as cenas de dor/Sentinela podem ser imagens geradas a partir de uma direção artística única, sem texto embutido. Requisições, respostas, estados e prova são componentes HTML/SVG para permanecer nítidos, traduzíveis e acessíveis. Cada cena tem um único objeto protagonista; a página evita grade repetida de três colunas, badges decorativos, gradientes genéricos e títulos centralizados com o mesmo subtítulo em todas as seções.

O movimento segue a causalidade: a superfície cresce, a requisição cruza a fronteira, a evidência aparece, o alerta emerge. As transições são breves, não prendem a leitura e obedecem a `prefers-reduced-motion`. O conteúdo permanece visível sem animação.

## Entrega e estados

O microsite é gerado como artefato estático em [`landing/`](../../../landing/README.md), independente do aplicativo Laravel. `/` serve inglês; `/pt-br/` serve português. O seletor preserva a âncora da cena, e `lang`, `hreflang`, metadados e nomes acessíveis correspondem ao idioma. A estrutura de conteúdo permite novas traduções sem duplicar lógica de interação. O domínio público final ainda precisa ser definido para gerar URLs absolutas de `hreflang` no deploy.

O CTA “Talk to a consultant” abre um aviso claro de que o agendamento estará disponível em breve. Quando a equipe fornecer a URL, o mesmo componente passa a abrir a agenda. Não haverá formulário que prometa contato sem canal de entrega.

## Sequência de trabalho com Impeccable

1. `$impeccable init`: registrar em `PRODUCT.md` o público, mecanismo e limites comprovados; confirmar somente lacunas materiais.
2. `$impeccable document`: extrair a identidade do app para `DESIGN.md` e o sidecar de tokens, sem substituir os ativos existentes.
3. `$impeccable shape landing`: consolidar narrativa, prova, idiomas e composição aprovada.
4. Produzir a composição e as ilustrações; depois usar `$impeccable distill`, `$impeccable layout` e `$impeccable typeset` para reduzir texto e ajustar ritmo e escala.
5. Usar `$impeccable animate` para o movimento causal; `$impeccable audit` e `$impeccable harden` para mobile, teclado, redução de movimento, tradução e estado do CTA.
6. Rodar o detector do Impeccable e conferir capturas desktop e mobile antes de publicar.

## Critérios de aceitação

- Quem chega entende a dor, o tipo de prova e o próximo passo na primeira visita.
- O visual remete à composição editorial da referência, mas usa logo, cor, conteúdo, arte e interfaces próprias da Égide.
- A história segue dor → prova → mural de riscos → método → Sentinela → conversa, com poucas frases de impacto.
- O mural tem escala verificável por CWE/CVE, com fonte pública acessível por link e data documentada nesta especificação; os cinco IDs CVE são links integrados às palavras. O tamanho não sugere prevalência em clientes ou capacidade de detecção da Égide.
- Nenhuma seção confunde mapeamento em produção com teste ativo, observação com achado, ou alerta com bloqueio.
- Inglês e português têm o mesmo percurso e CTAs; outros idiomas podem ser acrescentados sem refazer o layout.
- Desktop e mobile mantêm legibilidade, foco de teclado, contraste e alternativa sem movimento. Nas dimensões desktop verificadas, cada cena aparece inteira antes do próximo trecho.
- Rótulos funcionais mantêm tamanho legível no mobile e o texto atinge contraste WCAG AA; a identidade Inter/Manrope do app prevalece sobre avisos genéricos de fonte.

## Prévia para validação

A landing escolhida tem fonte em [`landing/src/page.html`](../../../landing/src/page.html) e saídas geradas em `landing/dist/`. A alternativa B foi descartada. A prova aparece como condição, sem atribuí-la a cliente; o quadro de evidência usa uma borda única, a primeira dobra aproxima o título da escultura e o método afasta o texto das divisórias. A nuvem de 27 classes e cinco links CVE fica entre prova e método. A revisão visual de EN e PT verificou 32 itens sem colisões nem rolagem horizontal em 1907 × 850, 1440 × 900, 1536 × 680 e 390 × 844. No mobile 390 × 844, as cenas foram ajustadas para caber na altura da tela. A moldura usa margem interna ampla e os links recebem foco visível pelo estilo global da página.

## Decisão pendente

URL final da agenda. Até lá, o aviso de agendamento futuro é parte do estado público aprovado.
