const wallWords = [...document.querySelectorAll(".wall-word[data-count]")];
const wallCounts = wallWords.map((el) => Number(el.dataset.count));
const wallMin = Math.log(Math.min(...wallCounts));
const wallRange = Math.log(Math.max(...wallCounts)) - wallMin;
wallWords.forEach((el) => {
    const rank = (Math.log(Number(el.dataset.count)) - wallMin) / wallRange;
    el.style.setProperty(
        "--word-size",
        Math.round(13 + 88 * Math.pow(rank, 2.7)) + "px",
    );
    el.style.setProperty(
        "--word-size-mobile",
        Math.round(14 + 20 * Math.pow(rank, 2.2)) + "px",
    );
});
const current = document.documentElement.lang === "pt-BR" ? "pt" : "en";
const describeWall = () => {
    document
        .querySelector(".word-wall")
        .setAttribute(
            "aria-label",
            current === "en"
                ? "Software weakness classes by public CVE volume"
                : "Classes de falhas de software por volume de CVEs públicos",
        );
    wallWords.forEach((el) => {
        const label = el.textContent;
        const count = new Intl.NumberFormat(
            current === "en" ? "en-US" : "pt-BR",
        ).format(Number(el.dataset.count));
        const description = `${label} · ${el.dataset.cwe} · ${count} ${current === "en" ? "public CVE records in NVD at the 17 Nov 2026 snapshot" : "registros CVE públicos na NVD no recorte de 17 nov. 2026"}`;
        el.title = description;
        el.setAttribute("aria-label", description);
    });
};
describeWall();
const cloud = document.querySelector(".word-wall");
const cloudCves = [...cloud.querySelectorAll(".cloud-cve-item")];
function packCloud() {
    if (window.innerWidth <= 1100) {
        cloud.classList.remove("is-packed");
        cloud.style.height = "";
        cloud.style.removeProperty("--cloud-scale");
        cloud.dataset.layout = "rows";
        return;
    }
    const width = cloud.clientWidth;
    const short = window.innerHeight < 741;
    const baseHeight = short
        ? 350
        : Math.min(462, Math.round(window.innerHeight * 0.54));
    const heights = short
        ? [baseHeight, 370]
        : [baseHeight, Math.min(baseHeight + 20, 480)];
    const pad = 8,
        gap = 7;
    let success = false;
    cloud.classList.add("is-packed");
    for (const height of heights) {
        cloud.style.height = height + "px";
        for (let scale = 1; scale >= 0.7; scale -= 0.03) {
            cloud.style.setProperty("--cloud-scale", scale.toFixed(2));
            const occupied = [],
                byKey = new Map();
            let complete = true;
            [...wallWords, ...cloudCves].forEach((el) => {
                el.style.setProperty("--cloud-x", "0px");
                el.style.setProperty("--cloud-y", "0px");
            });
            const free = (x, y, w, h) =>
                x >= pad &&
                y >= pad &&
                x + w <= width - pad &&
                y + h <= height - pad &&
                occupied.every(
                    (r) =>
                        x + w + gap <= r.x ||
                        x >= r.x + r.w + gap ||
                        y + h + gap <= r.y ||
                        y >= r.y + r.h + gap,
                );
            const find = (el, cx, cy, stretch, start = 0) => {
                const w = el.offsetWidth,
                    h = el.offsetHeight;
                for (
                    let radius = start;
                    radius < Math.max(width, height);
                    radius += 6
                ) {
                    const steps =
                        radius === 0
                            ? 1
                            : Math.max(
                                  12,
                                  Math.ceil((2 * Math.PI * radius) / 15),
                              );
                    for (let i = 0; i < steps; i++) {
                        const angle =
                            (i * 2 * Math.PI) / steps + 0.7 * occupied.length;
                        const x = Math.round(
                            cx + radius * Math.cos(angle) - w / 2,
                        );
                        const y = Math.round(
                            cy + radius * Math.sin(angle) * stretch - h / 2,
                        );
                        if (free(x, y, w, h)) return { x, y, w, h };
                    }
                }
                return null;
            };
            for (const el of wallWords) {
                const box = find(el, width / 2, height / 2, 0.62);
                if (!box) {
                    complete = false;
                    break;
                }
                occupied.push(box);
                byKey.set(el.dataset.key, box);
                el.style.setProperty("--cloud-x", box.x + "px");
                el.style.setProperty("--cloud-y", box.y + "px");
            }
            if (complete)
                for (const el of cloudCves) {
                    const parent = byKey.get(el.dataset.parent);
                    const box = find(
                        el,
                        parent.x + parent.w / 2,
                        parent.y + parent.h / 2,
                        0.9,
                        Math.max(parent.w, parent.h) / 2 + 12,
                    );
                    if (!box) {
                        complete = false;
                        break;
                    }
                    occupied.push(box);
                    el.style.setProperty("--cloud-x", box.x + "px");
                    el.style.setProperty("--cloud-y", box.y + "px");
                }
            if (complete) {
                success = true;
                cloud.dataset.scale = scale.toFixed(2);
                break;
            }
        }
        if (success) break;
    }
    if (!success) {
        cloud.classList.remove("is-packed");
        cloud.style.height = "";
        cloud.style.removeProperty("--cloud-scale");
        cloud.dataset.layout = "rows";
    } else cloud.dataset.layout = "packed";
}
document.fonts.ready.then(packCloud);
let cloudResize;
window.addEventListener("resize", () => {
    clearTimeout(cloudResize);
    cloudResize = setTimeout(packCloud, 100);
});
document.getElementById("locale").addEventListener("click", (event) => {
    if (!window.location.hash) return;
    event.preventDefault();
    window.location.assign(event.currentTarget.href + window.location.hash);
});
document.getElementById("booking-cta").addEventListener("click", () => {
    document.getElementById("booking-note").hidden = false;
});
const observer = new IntersectionObserver(
    (entries) =>
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add("is-visible");
                observer.unobserve(entry.target);
            }
        }),
    { threshold: 0.2 },
);
document
    .querySelectorAll(".boundary,.method-track")
    .forEach((el) => observer.observe(el));
