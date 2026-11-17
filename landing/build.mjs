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
const englishUrl = `${base}/`;
const portugueseUrl = `${base}/pt-br/`;

const aria = {
    en: {
        brandHome: "Égide AI home",
        mainNavigation: "Main navigation",
        talkAria: "Talk to a consultant",
        sculptureAria:
            "Paper sculpture of multiplying product routes crossed by a violet path",
        boundaryAria: "Account boundary diagram",
        evidenceAria: "IDOR proof rule",
        wallAria: "Software weakness classes with public CVE examples",
        methodAria: "How Égide works",
        sentinelAria: "Sentinela event path",
    },
    "pt-BR": {
        brandHome: "Página inicial da Égide AI",
        mainNavigation: "Navegação principal",
        talkAria: "Fale com um consultor",
        sculptureAria:
            "Escultura de papel com rotas de produto que se multiplicam, atravessadas por um caminho violeta",
        boundaryAria: "Diagrama da fronteira entre contas",
        evidenceAria: "Regra de confirmação de IDOR",
        wallAria: "Classes de falhas de software com exemplos de CVEs públicos",
        methodAria: "Como a Égide funciona",
        sentinelAria: "Caminho de eventos do Sentinela",
    },
};

const pages = [
    {
        lang: "en",
        out: "index.html",
        assetPrefix: "./",
        localeHref: "/pt-br/",
        localeSwitchLabel: "View the Brazilian Portuguese version",
        ogLocale: "en_US",
        title: "Égide AI — See the risk. Verify the finding.",
        description:
            "Your product scaled. Your security didn’t. See where access can fail, understand the proof, and talk to an Égide consultant.",
    },
    {
        lang: "pt-BR",
        out: "pt-br/index.html",
        assetPrefix: "../",
        localeHref: "/",
        localeSwitchLabel: "Ver a versão em inglês",
        ogLocale: "pt_BR",
        title: "Égide AI — Veja o risco. Confirme a falha.",
        description:
            "Seu produto escalou. Sua segurança, não. Entenda onde o acesso pode falhar, veja a prova e fale com um consultor da Égide.",
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
    html = html.replace(/\sdata-i18n="[^"]+"/g, "");
    const values = { ...page, englishUrl, portugueseUrl };
    html = html.replace(/\{\{(\w+)\}\}/g, (match, key) => {
        if (!(key in values)) throw new Error(`Missing template value: ${key}`);
        return escapeAttribute(values[key]);
    });
    return html;
}

await rm(dist, { recursive: true, force: true });
await mkdir(join(dist, "pt-br"), { recursive: true });
await mkdir(join(dist, "assets"), { recursive: true });
await cp(join(root, "src/assets"), join(dist, "assets"), { recursive: true });
await cp(join(root, "src/site.css"), join(dist, "assets/site.css"));
await cp(join(root, "src/site.js"), join(dist, "assets/site.js"));
for (const page of pages) await writeFile(join(dist, page.out), render(page));
console.log(`Built ${pages.length} landing pages in ${dist}`);
