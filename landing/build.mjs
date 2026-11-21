import { cp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const dist = resolve(root, "dist");
if (!dist.startsWith(root + sep))
    throw new Error("Refusing to clean outside landing/");
try {
    const target = await realpath(dist);
    if (!target.startsWith(root + sep))
        throw new Error("Refusing to clean a dist link outside landing/");
} catch (error) {
    if (error.code !== "ENOENT") throw error;
}

const template = await readFile(join(root, "src/page.html"), "utf8");
const pt = JSON.parse(await readFile(join(root, "src/copy.json"), "utf8"));
const base = process.env.LANDING_PUBLIC_URL?.replace(/\/+$/, "") ?? "";
if (base && !/^https:\/\/[^/]+$/.test(base)) {
    throw new Error("LANDING_PUBLIC_URL must be an HTTPS URL");
}
const englishUrl = `${base}/en/`;
const portugueseUrl = `${base}/`;

const aria = {
    en: {
        brandHome: "Égide AI home",
        mainNavigation: "Main navigation",
        tabsAria: "Proof examples",
        videoAria:
            "Égide AI session running: endpoints mapped, attacks attempted and flaws confirmed in real time",
        xssAlt: "DOM XSS finding with the screenshot taken at the moment of proof",
        fileAlt: "Path traversal finding returning the server passwd file",
        sqliAlt: "Boolean SQL injection finding with payload, rounds and HTTP results",
        bolaAlt: "Write BOLA finding: account A's session changed account B's record",
        scopeAlt: "Session rules: allowed and blocked routes enforced by the proxy",
        beforeAlt: "Session result with confirmed exposure and critical findings",
        afterAlt: "Retest result with account isolation confirmed",
    },
    "pt-BR": {
        brandHome: "Página inicial da Égide AI",
        mainNavigation: "Navegação principal",
        tabsAria: "Exemplos de prova",
        videoAria:
            "Sessão da Égide AI rodando: endpoints mapeados, ataques tentados e falhas confirmadas em tempo real",
        xssAlt: "Achado de XSS no DOM com a captura feita no instante da prova",
        fileAlt: "Achado de travessia de diretório devolvendo o arquivo passwd do servidor",
        sqliAlt: "Achado de injeção de SQL booleana com carga, rodadas e respostas HTTP",
        bolaAlt: "Achado de BOLA de escrita: a sessão da conta A alterou o registro da conta B",
        scopeAlt: "Regras da sessão: rotas permitidas e bloqueadas impostas pelo proxy",
        beforeAlt: "Resultado da sessão com exposição confirmada e falhas críticas",
        afterAlt: "Resultado do reteste com isolamento entre contas confirmado",
    },
};

const pages = [
    {
        lang: "en",
        out: "en/index.html",
        assetPrefix: "../",
        localeHref: "/",
        localeSwitchLabel: "View the Brazilian Portuguese version",
        ogLocale: "en_US",
        waUrl: "https://wa.me/5588993105030?text=" + encodeURIComponent("Hi! I would like to see Égide AI on my app."),
        title: "Égide AI — Every flaw, proven.",
        description:
            "Autonomous AI pentest: Égide attacks your app like an intruder and only reports what it proves, with evidence, scope enforced by a proxy and one-click retest.",
    },
    {
        lang: "pt-BR",
        out: "index.html",
        assetPrefix: "./",
        localeHref: "/en/",
        localeSwitchLabel: "Ver a versão em inglês",
        ogLocale: "pt_BR",
        waUrl: "https://wa.me/5588993105030?text=" + encodeURIComponent("Olá! Quero ver a Égide AI no meu app."),
        title: "Égide AI — Cada falha, provada.",
        description:
            "Pentest autônomo com IA: a Égide ataca seu app como um invasor e só reporta o que prova, com evidência, escopo travado por proxy e reteste em um clique.",
    },
];

function escapeAttribute(value) {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll('"', "&quot;")
        .replaceAll("<", "&lt;");
}

function render(page) {
    let html = template;
    if (page.lang === "pt-BR") {
        const translated = new Set();
        html = html.replace(
            /(<([a-z][\w-]*)\b[^>]*\bdata-i18n="([^"]+)"[^>]*>)([\s\S]*?)(<\/\2\s*>)/gi,
            (match, open, tag, key, original, close) => {
                if (!(key in pt))
                    throw new Error(`Missing Portuguese translation: ${key}`);
                translated.add(key);
                return open + pt[key] + close;
            },
        );
        const keys = [...template.matchAll(/\bdata-i18n="([^"]+)"/g)].map(
            (match) => match[1],
        );
        for (const key of keys)
            if (!translated.has(key))
                throw new Error(`Unrendered Portuguese key: ${key}`);
    }
    html = html.replace(/<[^>]+\bdata-i18n-aria="([^"]+)"[^>]*>/g, (tag) => {
        const key = tag.match(/\bdata-i18n-aria="([^"]+)"/)[1];
        const label = aria[page.lang][key];
        if (!label) throw new Error(`Missing aria label: ${page.lang}/${key}`);
        return tag
            .replace(/\sdata-i18n-aria="[^"]+"/, "")
            .replace(
                /\saria-label="[^"]*"/,
                ` aria-label="${escapeAttribute(label)}"`,
            );
    });
    html = html.replace(/<[^>]+\bdata-i18n-alt="([^"]+)"[^>]*>/g, (tag) => {
        const key = tag.match(/\bdata-i18n-alt="([^"]+)"/)[1];
        const label = aria[page.lang][key];
        if (!label) throw new Error(`Missing alt text: ${page.lang}/${key}`);
        return tag
            .replace(/\sdata-i18n-alt="[^"]+"/, "")
            .replace(/\salt="[^"]*"/, ` alt="${escapeAttribute(label)}"`);
    });
    html = html.replace(/\sdata-i18n="[^"]+"/g, "");
    const values = { ...page, englishUrl, portugueseUrl };
    html = html.replace(/\{\{(\w+)\}\}/g, (match, key) => {
        if (!(key in values)) throw new Error(`Missing template value: ${key}`);
        return escapeAttribute(values[key]);
    });
    return html;
}

await rm(dist, { recursive: true, force: true });
await mkdir(join(dist, "en"), { recursive: true });
await mkdir(join(dist, "assets"), { recursive: true });
await cp(join(root, "src/assets"), join(dist, "assets"), { recursive: true });
await cp(join(root, "src/site.css"), join(dist, "assets/site.css"));
await cp(join(root, "src/site.js"), join(dist, "assets/site.js"));
for (const page of pages) await writeFile(join(dist, page.out), render(page));
console.log(`Built ${pages.length} landing pages in ${dist}`);
