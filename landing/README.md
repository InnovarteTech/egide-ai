# Landing pública da Égide AI

A Landing A é um microsite estático independente do console Laravel. O português brasileiro fica em `/` (padrão); o inglês, em `/en/`. `/pt-br/` redireciona para `/`. Os links de idioma preservam a âncora da seção aberta.

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

O diretório `landing/dist/` é gerado e ignorado pelo Git. Configure a hospedagem estática para executar o build e servir esse diretório na raiz do domínio. No build de produção, defina `LANDING_PUBLIC_URL=https://seu-dominio` para gerar URLs absolutas de `hreflang`. Sem a variável, os links usam `/` e `/en/` para a prévia local.

Os botões “Fale com um consultor” abrem o WhatsApp comercial (+55 88 99310-5030) com mensagem pronta no idioma da página. Não há envio de formulário.

## Fonte e ativos

- O logo é uma cópia de [`public/egide.svg`](../public/egide.svg) para que o microsite seja implantado sozinho.
- O vídeo `sessao-ao-vivo.mp4` é um timelapse de uma sessão real no laboratório da Égide (falhas plantadas, sessão PT-C56675); os prints `prova-*.webp` e `product-*.webp` são capturas reais dessa sessão e do reteste.
- Inter Variable e Manrope Variable são servidas localmente. As licenças SIL OFL acompanham os arquivos em `src/assets/fonts/`.
