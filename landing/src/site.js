document.getElementById("locale").addEventListener("click", (event) => {
    if (!window.location.hash) return;
    event.preventDefault();
    window.location.assign(event.currentTarget.href + window.location.hash);
});
const video = document.querySelector(".session video");
if (video && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    video.removeAttribute("autoplay");
    video.pause();
    video.controls = true;
}
const tabs = [...document.querySelectorAll('[role="tab"]')];
const select = (tab) => {
    tabs.forEach((t) => {
        const on = t === tab;
        t.setAttribute("aria-selected", on);
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    });
};
tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => select(tab));
    tab.addEventListener("keydown", (e) => {
        const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (!d) return;
        const next = tabs[(i + d + tabs.length) % tabs.length];
        select(next);
        next.focus();
    });
});
