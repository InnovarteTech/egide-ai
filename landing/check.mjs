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

const examples = [
    ["XSS", "CVE-2024-11846"],
    ["SQLi", "CVE-2023-34362"],
    ["IDOR", "CVE-2024-42169"],
    ["SSRF", "CVE-2021-26855"],
    ["CSRF", "CVE-2024-13244"],
];
const pages = [
    {
        path: "index.html",
        lang: "en",
        hero: "Your product",
        cta: "Talk to a consultant",
        event: "access denied",
        locale: "/pt-br/",
    },
    {
        path: "pt-br/index.html",
        lang: "pt-BR",
        hero: "Seu produto",
        cta: "Fale com um consultor",
        event: "acesso negado",
        locale: "/",
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
    assert.ok(html.includes(page.event), `${page.path}: missing Sentinela event`);
    assert.ok(new RegExp(`<a[^>]*id="locale"[^>]*href="${page.locale}"`, 's').test(html), `${page.path}: wrong language link`);
    assert.ok(/<small[^>]*id="booking-note"[^>]*\bhidden\b/s.test(html), `${page.path}: booking note must start hidden`);
    assert.equal((html.match(/class="wall-word"/g) ?? []).length, 27);
    assert.equal((html.match(/class="cloud-cve"/g) ?? []).length, 5);
    for (const [label, cve] of examples) {
        assert.ok(html.includes(`${label} / ${cve}`));
        assert.ok(html.includes(`https://nvd.nist.gov/vuln/detail/${cve}`));
    }
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
    "Landing checks passed: locales, metadata, links, CVEs, assets, and booking state.",
);
