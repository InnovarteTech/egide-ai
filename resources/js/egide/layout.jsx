import { useEffect, useState } from 'react';
import { Head, Link, router, usePage } from '@inertiajs/react';
import { Check, ChevronDown, CirclePlay, Crosshair, Layers3, LayoutGrid, LogOut, Menu, Radio, Settings2, Shield, ShieldAlert } from 'lucide-react';
import { Logo } from './ui';

const navigation = [
    ['Visão geral', '/', LayoutGrid],
    ['Ativos', '/ativos', Layers3],
    ['Sessões', '/sessoes', CirclePlay],
    ['Achados', '/achados', Crosshair],
    ['Sentinela', '/sentinela', Radio],
];
const preload = { prefetch: 'hover', cacheFor: '10s' };
function Sidebar({ open, close }) {
    const { url, props } = usePage();
    const name = props.workspace?.name ?? 'Meu workspace';
    const initials = name.split(/\s+/).slice(0, 2).map(word => word[0]).join('').toUpperCase();
    useEffect(() => {
        if (!open) return;
        const current = url.split('?')[0];
        [...navigation.map(([, href]) => href), props.auth?.is_admin ? '/admin' : null, '/configuracoes']
            .filter(href => href && href !== current)
            .forEach(href => router.prefetch(href, {}, { cacheFor: '10s' }));
    }, [open]);
    return <>
        {open && <button type="button" className="mobile-scrim" onClick={close} aria-label="Fechar menu" />}
        <aside className={'sidebar ' + (open ? 'sidebar-open' : '')} aria-label="Navegação principal">
            <Link href="/" className="sidebar-logo" onClick={close}><Logo /></Link>
            <div className="workspace">
                <span className="micro">WORKSPACE</span>
                <Link href="/configuracoes" className="workspace-name" onClick={close}><span>{name}</span><ChevronDown size={15} /></Link>
            </div>
            <nav className="nav-main">
                <div className="micro nav-section">OPERAÇÃO</div>
                {navigation.map(([label, href, Icon]) => {
                    const active = href === '/' ? url === '/' : url.startsWith(href);
                    return <Link key={href} href={href} {...preload} onClick={close} className={'nav-link ' + (active ? 'nav-active' : '')} aria-current={active ? 'page' : undefined}>
                        <Icon size={19} /><span>{label}</span>{active && <i />}
                    </Link>;
                })}
            </nav>
            <div className="sidebar-bottom">
                {props.auth?.is_admin && <Link className={'nav-link ' + (url.startsWith('/admin') ? 'nav-active' : '')} href="/admin" {...preload} onClick={close}><ShieldAlert size={19} />Super admin</Link>}
                <Link className={'nav-link ' + (url.startsWith('/configuracoes') ? 'nav-active' : '')} href="/configuracoes" {...preload} onClick={close}><Settings2 size={19} />Configurações</Link>
                <div className="account">
                    <span className="avatar">{initials}</span>
                    <div className="account-meta"><strong>{props.auth?.name}</strong><small>{props.auth?.email}</small></div>
                    <Link href="/sair" method="post" as="button" className="icon-button" title="Sair" aria-label="Sair"><LogOut size={17} /></Link>
                </div>
            </div>
        </aside>
    </>;
}
export function Layout({ title, children }) {
    const [menu, setMenu] = useState(false);
    const { props } = usePage();
    return <div className="shell" style={{ '--accent': props.workspace?.accent ?? '#6435ea' }}>
        <Head title={title} />
        <Sidebar open={menu} close={() => setMenu(false)} />
        <main className="main">
            <div className="topline">
                <button type="button" className="icon-button menu-button" onClick={() => setMenu(true)} aria-label="Abrir menu"><Menu size={21} /></button>
                <div className="breadcrumb"><span className="signal" /><span>Workspace</span><span className="slash">/</span><strong>{title}</strong></div>
                <span className="environment"><Shield size={15} /> Defesa autorizada</span>
            </div>
            {props.flash && <div role="status" className="notice"><Check size={16} />{props.flash}</div>}
            {children}
        </main>
    </div>;
}
export function Heading({ title, description, children }) {
    return <header className="heading"><div><h1>{title}</h1>{description && <p>{description}</p>}</div>{children && <div className="heading-actions">{children}</div>}</header>;
}
