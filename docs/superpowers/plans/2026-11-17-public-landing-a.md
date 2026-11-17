# Landing pública A — plano de entrega

**Objetivo:** transformar a direção visual A aprovada em um microsite estático, independente do console Laravel, pronto para revisão e hospedagem.

## Escopo

- Inglês em `/` e português brasileiro em `/pt-br/`, com HTML, metadados e nomes acessíveis próprios de cada idioma.
- Manter a narrativa aprovada: produto que escala, risco de acesso, prova objetiva, mural de falhas e CVEs, método, Sentinela e conversa com consultor.
- Reutilizar o logo do produto e a escultura de rotas aprovada. O destino da agenda permanece mock, com mensagem honesta ao clicar.
- Preservar o contrato do produto: testes ativos somente em ambientes autorizados; em produção, mapeamento e configuração; Sentinela monitora eventos e alerta.

## Implementação

1. Criar `landing/` com fonte HTML, CSS, JS e dados de tradução; gerar `landing/dist/` por um script Node sem dependências externas.
2. Extrair o mock aprovado, retirar referências a estudo visual e arquivos temporários, corrigir o exemplo de evento do Sentinela e tornar o idioma um link entre páginas que mantém a âncora atual.
3. Gerar as duas páginas estáticas, incluindo `lang`, descrição, metadados sociais, `hreflang`, texto alternativo e nomes acessíveis traduzidos. Compartilhar CSS, JS, fontes e imagens.
4. Adicionar uma verificação de build que confira os dois idiomas, arquivos e links locais, os cinco CVEs, o CTA mock e a ausência de texto temporário ou chaves não resolvidas.
5. Revisar em navegador desktop e mobile, teclado, motion reduzido e disponibilidade do aviso de agendamento; corrigir problemas observados.
6. Atualizar a especificação e o índice técnico com o caminho final; excluir `.superpowers/` e `.codex/` temporários do PR após migrar os ativos; revisar o diff.
7. Comitar na branch `feat/public-landing-a`, enviar ao remoto e abrir um PR para `main` com resultado e verificações.

## Verificação

- `node landing/build.mjs`
- `node landing/check.mjs`
- `git diff --check`
- Revisão visual de `/` e `/pt-br/` em larguras desktop e mobile, incluindo mural e interação do CTA.

Não há mudança no fluxo Laravel, runner ou proxy. As suítes PHP e Python não são um gate para este PR de microsite estático.
