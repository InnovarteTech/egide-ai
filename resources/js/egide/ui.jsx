import React, { useEffect, useId, useRef, useState } from 'react';
import { Link, router } from '@inertiajs/react';
import { ArrowLeft, ArrowRight, Check, Copy, TriangleAlert, X } from 'lucide-react';
import { statuses } from './format';

export function Logo() {
    return <div className="logo"><img src="/egide.svg" alt="" width="36" height="36" /><span>Égide<span className="logo-period"> AI</span></span></div>;
}
export function Badge({ children, tone = 'neutral' }) {
    return <span className={'badge ' + tone}><i />{children}</span>;
}
export function Status({ status }) {
    const [label, tone] = statuses[status] ?? [status, 'neutral'];
    return <Badge tone={tone}>{label}</Badge>;
}
export function useTab(name, fallback, allowed) {
    const [tab, setTab] = useState(() => {
        if (typeof window === 'undefined') return fallback;
        const value = new URLSearchParams(window.location.search).get(name);
        return allowed.includes(value) ? value : fallback;
    });
    const change = value => {
        setTab(value);
        const url = new URL(window.location.href);
        if (value === fallback) url.searchParams.delete(name); else url.searchParams.set(name, value);
        window.history.replaceState(window.history.state, '', url);
    };
    return [tab, change];
}
export function Tabs({ name, label, tabs, value, onChange, className = '' }) {
    useEffect(() => {
        const tab = document.getElementById(name + '-tab-' + value);
        const bar = tab?.closest('.tabbar');
        if (!bar || bar.scrollWidth <= bar.clientWidth) return;
        const offset = tab.getBoundingClientRect().left - bar.getBoundingClientRect().left;
        if (offset < 0 || offset + tab.offsetWidth > bar.clientWidth) bar.scrollLeft += offset - (bar.clientWidth - tab.offsetWidth) / 2;
    }, [name, value]);
    const move = (event, index) => {
        const offsets = { ArrowRight: 1, ArrowLeft: -1 };
        let next = null;
        if (event.key in offsets) next = (index + offsets[event.key] + tabs.length) % tabs.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = tabs.length - 1;
        if (next === null) return;
        event.preventDefault();
        onChange(tabs[next].key);
        document.getElementById(name + '-tab-' + tabs[next].key)?.focus();
    };
    return <div role="tablist" aria-label={label} className={'tabbar ' + className}>
        {tabs.map((tab, index) => <button key={tab.key} type="button" role="tab" id={name + '-tab-' + tab.key}
            aria-selected={value === tab.key} aria-controls={value === tab.key ? name + '-panel-' + tab.key : undefined} tabIndex={value === tab.key ? 0 : -1}
            onClick={() => onChange(tab.key)} onKeyDown={event => move(event, index)}>
            {tab.icon && <tab.icon size={16} />}
            {tab.step && <span className="tab-step" aria-hidden="true">{tab.step}</span>}
            <span>{tab.label}</span>
            {tab.count !== undefined && <span className={'tab-count ' + (tab.tone ?? '')}>{tab.count}</span>}
            {tab.alert && <><i className="tab-alert" aria-hidden="true" /><span className="sr-only">, revise os campos</span></>}
        </button>)}
    </div>;
}
export function TabPanel({ name, id, children, className = '' }) {
    return <div role="tabpanel" id={name + '-panel-' + id} aria-labelledby={name + '-tab-' + id} className={'tabpanel ' + className}>{children}</div>;
}
export function Dialog({ open, onClose, title, description, children, footer, size = '', locked = false }) {
    const ref = useRef(null);
    const pressedBackdrop = useRef(false);
    const id = useId();
    useEffect(() => {
        const node = ref.current;
        if (!node) return;
        if (open && !node.open) {
            node.showModal();
            node.querySelector('[data-autofocus]')?.focus();
        }
        if (!open && node.open) node.close();
    }, [open]);
    return <dialog ref={ref} className={'dialog ' + size} aria-labelledby={id} aria-describedby={description ? id + '-description' : undefined} onClose={() => open && onClose()}
        onCancel={event => { if (locked) event.preventDefault(); }}
        onMouseDown={event => { pressedBackdrop.current = event.target === ref.current; }}
        onClick={event => { if (pressedBackdrop.current && event.target === ref.current) onClose(); }}>
        {open && <div className="dialog-panel">
            <header className="dialog-head">
                <div><h2 id={id}>{title}</h2>{description && <p id={id + '-description'}>{description}</p>}</div>
                <button type="button" className="icon-button" onClick={onClose} aria-label="Fechar"><X size={18} /></button>
            </header>
            <div className="dialog-body">{children}</div>
            {footer && <footer className="dialog-foot">{footer}</footer>}
        </div>}
    </dialog>;
}
export function ConfirmAction({ href, method = 'post', data, title, description, confirmLabel, tone = 'danger', className = 'button secondary compact', children }) {
    const [open, setOpen] = useState(false);
    const [busy, setBusy] = useState(false);
    const run = () => router.visit(href, {
        method, data, preserveScroll: true, preserveState: true,
        onStart: () => setBusy(true),
        onFinish: () => { setBusy(false); setOpen(false); },
    });
    return <>
        <button type="button" className={className} onClick={() => setOpen(true)}>{children}</button>
        <Dialog open={open} onClose={() => !busy && setOpen(false)} locked={busy} title={title} size="dialog-sm" footer={<>
            <button type="button" className="button secondary" onClick={() => setOpen(false)} disabled={busy} data-autofocus>Cancelar</button>
            <button type="button" className={'button ' + (tone === 'danger' ? 'danger' : 'primary')} onClick={run} disabled={busy}>{busy ? 'Processando…' : confirmLabel}</button>
        </>}>
            <p className="dialog-text">{description}</p>
        </Dialog>
    </>;
}
export function CopyBox({ value, label = 'Copiar' }) {
    const [copied, setCopied] = useState(false);
    return <div className="copy-box">
        <code>{value}</code>
        <button type="button" className="button secondary compact" onClick={() => navigator.clipboard?.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1600); })}>
            {copied ? <Check size={15} /> : <Copy size={15} />}{copied ? 'Copiado' : label}
        </button>
    </div>;
}
export function Empty({ icon: Icon, title, children, action }) {
    return <div className="empty">
        <span className="empty-icon"><Icon size={22} /></span>
        <strong>{title}</strong>
        {children && <p>{children}</p>}
        {action}
    </div>;
}
export function Field({ label, error, help, children, className = '' }) {
    const generated = useId();
    const id = children?.props?.id ?? generated;
    const describedBy = [help && id + '-help', error && id + '-error'].filter(Boolean).join(' ') || undefined;
    const control = React.isValidElement(children)
        ? React.cloneElement(children, { id, 'aria-invalid': error ? true : undefined, 'aria-describedby': describedBy })
        : children;
    return <div className={'field ' + (error ? 'has-error ' : '') + className}>
        <label htmlFor={id}>{label}</label>
        {control}
        {help && !error && <small id={id + '-help'}>{help}</small>}
        {error && <small id={id + '-error'} className="field-error" role="alert"><TriangleAlert size={13} />{error}</small>}
    </div>;
}
export function Pagination({ links }) {
    const previous = links?.[0];
    const next = links?.at(-1);
    if (!previous?.url && !next?.url) return null;
    return <div className="pagination">{previous?.url && <Link className="button secondary compact" href={previous.url} preserveScroll><ArrowLeft size={16} /> Anterior</Link>}{next?.url && <Link className="button secondary compact" href={next.url} preserveScroll>Próxima <ArrowRight size={16} /></Link>}</div>;
}
export function Orbit() {
    return <svg className="orbit" viewBox="0 0 530 260" fill="none" aria-hidden="true">
        <defs>
            <radialGradient id="orbitGlow"><stop stopColor="#a481ff" stopOpacity=".25" /><stop offset="1" stopColor="#a481ff" stopOpacity="0" /></radialGradient>
            <linearGradient id="orbitalLine"><stop stopColor="#7858ef" stopOpacity=".15" /><stop offset=".55" stopColor="#ae91ff" /><stop offset="1" stopColor="#9271ff" stopOpacity=".35" /></linearGradient>
        </defs>
        <circle cx="299" cy="132" r="137" fill="url(#orbitGlow)" />
        <g stroke="#9874fa">
            <circle cx="299" cy="132" r="111" strokeOpacity=".7" strokeDasharray="1 5" strokeWidth="3" />
            <circle cx="299" cy="132" r="90" strokeOpacity=".68" />
            <circle cx="299" cy="132" r="70" strokeOpacity=".28" />
            <circle cx="299" cy="132" r="51" strokeOpacity=".2" />
            <path d="M299 12v64m0 112v58M175 132h69m110 0h73" strokeOpacity=".62" />
            <ellipse cx="301" cy="130" rx="227" ry="48" transform="rotate(-16 301 130)" stroke="url(#orbitalLine)" strokeWidth="1.4" />
            <path d="M51 62v-12h12m442 25V63h-12M75 220v12h12m415-1v-12h-12" strokeOpacity=".65" />
            <path d="M128 66v15m-7-7h15m309 100v18m-9-9h18" strokeOpacity=".65" />
        </g>
        <circle cx="463" cy="95" r="7" fill="#9c74ff" opacity=".25" />
        <circle cx="463" cy="95" r="4" fill="#d3bdff" />
        <circle cx="151" cy="170" r="3" fill="#b59aff" />
        <path d="M278 124v-13h13m16 0h13v13m0 16v13h-13m-16 0h-13v-13" stroke="#c4a9ff" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="299" cy="132" r="4.5" fill="#f1e8ff" />
    </svg>;
}
