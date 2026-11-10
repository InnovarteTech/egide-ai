import { useEffect } from 'react';
import { Link, router, useForm } from '@inertiajs/react';
import { ArrowRight, ArrowUpRight, CirclePlay, Crosshair, Fingerprint, Layers3, Monitor, Plus, ScanLine, ShieldCheck } from 'lucide-react';
import { outcomes, captureAge, formatDate, formatTime, scanLabel } from '../format';
import { Status, Empty, Orbit } from '../ui';
import { Layout, Heading } from '../layout';

const steps = [
    ['Autorização', 'Defina o alvo e as permissões do teste.', ShieldCheck],
    ['Exploração', 'Acompanhe o Firefox e as chamadas observadas.', ScanLine],
    ['Evidência', 'Confira o achado e repita o teste após a correção.', Fingerprint],
];
function ScanTable({ scans }) {
    if (!scans.length) return <Empty icon={CirclePlay} title="Nenhuma sessão registrada" action={<Link href="/sessoes/nova" className="text-link">Configurar uma sessão <ArrowRight size={16} /></Link>}>
        Execute o laboratório para acompanhar sua primeira avaliação.
    </Empty>;
    return <div className="table-scroll scan-table"><table>
        <thead><tr><th>Sessão</th><th>Ambiente</th><th>Início</th><th>Estado</th><th><span className="sr-only">Abrir</span></th></tr></thead>
        <tbody>{scans.map(scan => <tr key={scan.id}>
            <td><Link href={'/sessoes/' + scan.id} className="mono scan-id">{scanLabel(scan)}</Link></td>
            <td>{scan.name}</td><td className="muted">{formatDate(scan.created_at)}</td><td><Status status={scan.status} /></td>
            <td><Link href={'/sessoes/' + scan.id} className="icon-button" aria-label={'Abrir ' + scanLabel(scan)}><ArrowUpRight size={17} /></Link></td>
        </tr>)}</tbody>
    </table></div>;
}
const severityBars = [['critical', 'Crítica', '#c4304b'], ['high', 'Alta', '#d9711c'], ['medium', 'Média', '#6435ea'], ['low', 'Baixa', '#a99fc2']];
function Spotlight({ scan }) {
    const live = ['queued', 'running'].includes(scan.status);
    const progress = Math.min(100, Math.round((scan.request_count / Math.max(1, scan.budget)) * 100));
    const tone = { finding: 'event-red', verified: 'event-green' };
    return <section className="hero hero-live">
        <div className="hero-live-text">
            <div className="hero-title">
                <h2>{scan.name}</h2>
                <span className={'hero-status ' + (live ? 'is-live' : '')}><i />{live ? 'Ao vivo' : 'Última sessão'} · {scanLabel(scan)}</span>
            </div>
            <div className="hero-progress" role="progressbar" aria-label="Requisições usadas" aria-valuenow={progress} aria-valuemin="0" aria-valuemax="100"><span style={{ transform: 'scaleX(' + progress / 100 + ')' }} /></div>
            <ol className="hero-events">{scan.events.map(event => <li key={event.id}><time>{formatTime(event.created_at)}</time><span className={tone[event.type] ?? ''}>{event.title === 'Ação selecionada pela IA' ? 'IA escolheu: ' + event.detail : event.title}</span></li>)}</ol>
            <span className="hero-meta">{scan.engine}{scan.model ? ' · ' + scan.model : ''} · {scan.request_count} de {scan.budget} requisições{scan.blocked_count ? ' · ' + scan.blocked_count + ' barrada(s) pelo escopo' : ''}</span>
            <div className="hero-actions">
                <Link href={'/sessoes/' + scan.id} className="button white">{live ? 'Acompanhar ao vivo' : 'Abrir sessão'} <ArrowRight size={17} /></Link>
                {!live && <Link href={'/sessoes/' + scan.id + '/relatorio/imprimir'} className="button ghost">Ver relatório</Link>}
            </div>
        </div>
        <figure className="hero-frame">
            {scan.frame ? <img src={'/sessoes/' + scan.id + '/imagem?v=' + encodeURIComponent(scan.updated_at)} alt="Última captura do Firefox isolado" /> : <div className="hero-frame-empty"><Monitor size={28} /><span>A captura aparece quando o Firefox abre.</span></div>}
            {live && scan.frame && scan.frame_at && <span className="frame-stamp">Captura automática · {captureAge(scan.frame_at)}</span>}
            <figcaption>Firefox isolado · {live ? scan.phase : (outcomes[scan.result]?.[0] ?? scan.phase)}</figcaption>
        </figure>
    </section>;
}
export function Overview({ scans, stats, agentAvailable, spotlight }) {
    const lab = useForm({ mode: 'laboratory', budget: 600, agent: agentAvailable });
    const live = spotlight && ['queued', 'running'].includes(spotlight.status);
    useEffect(() => {
        if (!live) return undefined;
        const timer = setInterval(() => router.reload({ only: ['spotlight', 'scans', 'stats'] }), 4000);
        return () => clearInterval(timer);
    }, [live]);
    const severity = spotlight?.severity ?? {};
    const total = severityBars.reduce((sum, [key]) => sum + (severity[key] ?? 0), 0);
    const top = Math.max(1, ...severityBars.map(([key]) => severity[key] ?? 0));
    return <Layout title="Visão geral">
        <Heading title="Visão geral" description="Acompanhe suas sessões e valide a segurança dos seus ambientes.">
            <Link href="/sessoes/nova" className="button primary"><Plus size={19} /> Nova sessão</Link>
        </Heading>
        {spotlight ? <Spotlight scan={spotlight} /> : <section className="hero">
            <Orbit />
            <div className="hero-content">
                <h2>Laboratório de autorização</h2>
                <p>Investigue uma falha de acesso entre empresas em um ambiente controlado.</p>
                <button type="button" className="button white" disabled={lab.processing} onClick={() => lab.post('/sessoes')}>
                    {lab.processing ? 'Enviando para a fila…' : agentAvailable ? 'Executar laboratório com IA' : 'Executar laboratório'} <ArrowRight size={17} />
                </button>
                {lab.errors.agent && <p role="alert">{lab.errors.agent}</p>}
                {lab.errors.mode && <p role="alert">{lab.errors.mode}</p>}
            </div>
        </section>}
        <div className="metrics">
            {[
                ['Ambientes verificados', stats.assets, Layers3, '/ambientes', 'Domínios autorizados'],
                ['Sessões realizadas', stats.sessions, CirclePlay, '/sessoes', stats.active ? stats.active + ' em andamento' : 'Concluídas'],
                ['Achados confirmados', stats.findings, Crosshair, '/achados', 'Com evidência'],
            ].map(([label, value, Icon, href, caption]) => <Link href={href} key={label} className="metric">
                <span className="metric-icon"><Icon size={23} /></span>
                <div><div className="metric-label">{label}</div><strong>{value}</strong></div><small>{caption}</small>
            </Link>)}
        </div>
        <div className="overview-columns">
            <section className="panel">
                <div className="panel-header"><h2>Sessões recentes</h2><Link href="/sessoes" className="text-link">Ver todas <ArrowRight size={16} /></Link></div>
                <ScanTable scans={scans} />
            </section>
            {spotlight && total > 0 ? <section className="panel severity-panel">
                <div className="panel-header"><div><h2>Achados por severidade</h2><p>{scanLabel(spotlight)} · {spotlight.name}</p></div></div>
                <div className="severity-bars">
                    {severityBars.map(([key, label, color]) => <div key={key} className="severity-bar"><span>{label}</span><span className="severity-track"><span style={{ width: Math.round(((severity[key] ?? 0) / top) * 100) + '%', background: color }} /></span><strong>{severity[key] ?? 0}</strong></div>)}
                    <Link href={'/sessoes/' + spotlight.id + '/relatorio/imprimir'} className="text-link">Abrir relatório <ArrowRight size={16} /></Link>
                </div>
            </section> : <section className="panel workflow">
                <div className="panel-header"><div><h2>Fluxo da avaliação</h2><p>Da permissão ao reteste.</p></div></div>
                <ol>{steps.map(([title, description, Icon]) => <li key={title}><span className="step-icon"><Icon size={18} /></span><div><strong>{title}</strong><p>{description}</p></div></li>)}</ol>
            </section>}
        </div>
    </Layout>;
}
