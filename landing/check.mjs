import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "dist");
const css = await readFile(join(dist, "assets/site.css"), "utf8");
const js = await readFile(join(dist, "assets/site.js"), "utf8");
assert.match(css, /\[hidden\]\s*\{\s*display:\s*none\s*!important\s*;?\s*\}/);
assert.match(js, /location\.hash/);

const pages = [
    {
        path: "en/index.html",
        lang: "en",
        hero: "Every flaw",
        cta: "Talk to a consultant",
        event: "flaws proven",
        locale: "/",
    },
    {
        path: "index.html",
        lang: "pt-BR",
        hero: "Cada falha",
        cta: "Fale com um consultor",
        event: "falhas provadas",
        locale: "/en/",
    },
];

for (const page of pages) {
    const file = join(dist, page.path);
    const html = await readFile(file, "utf8");
    assert.match(html, new RegExp(`<html lang="${page.lang}">`));
    assert.match(html, /<title>Égide AI — [^<]+<\/title>/);
    assert.ok(/<meta name="description" content="[^"]+"\s*\/>/.test(html), `${page.path}: missing description`);
    assert.ok(/<meta property="og:description" content="[^"]+"\s*\/>/.test(html), `${page.path}: missing social description`);
    assert.match(html, /hreflang="en"/);
    assert.match(html, /hreflang="pt-BR"/);
    assert.ok(html.includes(page.hero));
    assert.ok(html.includes(page.cta));
    assert.ok(html.includes(page.event), `${page.path}: missing stats`);
    assert.ok(new RegExp(`<a[^>]*id="locale"[^>]*href="${page.locale}"`, 's').test(html), `${page.path}: wrong language link`);
    assert.equal((html.match(/href="https:\/\/wa\.me\/5588993105030\?text=[^"]+"/g) ?? []).length, 3, `${page.path}: consultant CTAs must open WhatsApp`);
    assert.ok(html.includes("sessao-ao-vivo.mp4"), `${page.path}: missing session video`);
    assert.equal((html.match(/<img [^>]*alt="[^"]+"/g) ?? []).length, 7);
    assert.doesNotMatch(
        html,
        /\{\{|visual direction study|synthetic lab|illustrative|Human threats|Word size:/i,
    );
    assert.doesNotMatch(html, /data-i18n-aria/);

    const ids = new Set(
        [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]),
    );
    const refs = [...html.matchAll(/\b(?:href|src)="([^"]+)"/g)].map(
        (match) => match[1],
    );
    for (const ref of refs) {
        if (/^https?:\/\//.test(ref)) continue;
        if (ref.startsWith("#")) {
            assert.ok(
                ids.has(ref.slice(1)),
                `${page.path}: missing anchor ${ref}`,
            );
            continue;
        }
        const target = ref.startsWith("/")
            ? join(dist, ref, "index.html")
            : resolve(dirname(file), ref);
        await stat(target).catch(() => {
            throw new Error(`${page.path}: missing asset or route ${ref}`);
        });
    }
}

for (const match of css.matchAll(/url\(['"]?([^'"\)]+)['"]?\)/g)) {
    await stat(resolve(dist, "assets", match[1])).catch(() => {
        throw new Error(`Missing font asset: ${match[1]}`);
    });
}

console.log(
    "Landing checks passed: locales, metadata, links, video, alt text, assets, and WhatsApp CTAs.",
);
