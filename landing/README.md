# Landing pública da Égide AI

A Landing A é um microsite estático independente do console Laravel. O inglês fica em `/`; o português brasileiro, em `/pt-br/`. Os links de idioma preservam a âncora da seção aberta.

## Gerar e verificar

Na raiz do repositório, com Node instalado:

```bash
node landing/build.mjs
node landing/check.mjs
```

Para abrir localmente, sirva `landing/dist/` como raiz HTTP, por exemplo:

```bash
python -m http.server 4173 --directory landing/dist
```

O diretório `landing/dist/` é gerado e ignorado pelo Git. Configure a hospedagem estática para executar o build e servir esse diretório na raiz do domínio. No build de produção, defina `LANDING_PUBLIC_URL=https://seu-dominio` para gerar URLs absolutas de `hreflang`. Sem a variável, os links usam `/` e `/pt-br/` para a prévia local.

O botão de conversa com consultor mostra “Booking opens soon” / “Agendamento em breve” enquanto a URL da agenda não estiver disponível. Não há envio de formulário.

## Fonte e ativos

- O logo é uma cópia de [`public/egide.svg`](../public/egide.svg) para que o microsite seja implantado sozinho.
- A escultura de rotas foi criada para a direção visual aprovada da Égide.
- Inter Variable e Manrope Variable são servidas localmente. As licenças SIL OFL acompanham os arquivos em `src/assets/fonts/`.
- O mural usa classes CWE e exemplos CVE documentados na [especificação](../docs/superpowers/specs/2026-11-17-egide-landing-design.md). As contagens são um recorte do NVD, não uma métrica de clientes ou da cobertura da Égide.
