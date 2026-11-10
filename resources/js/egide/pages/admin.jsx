import { Link, useForm, usePage } from '@inertiajs/react';
import { Activity, Check, CirclePlay, Layers3, LockKeyhole, OctagonX, Pause, Play, PlugZap, Square, UserX, Users } from 'lucide-react';
import { outcomes, severities, scanLabel, plural } from '../format';
import { Badge, Status, useTab, Tabs, TabPanel, ConfirmAction, Empty, Field } from '../ui';
import { Layout, Heading } from '../layout';

function AdminScans({ scans, stoppable }) {
    if (!scans.length) return <Empty icon={CirclePlay} title={'Nenhuma sessão ' + (stoppable ? 'ativa' : 'registrada')} />;
    return <div className="table-scroll"><table className="data-table">
        <thead><tr><th>Sessão</th><th>Conta</th><th className="hide-sm">Alvo</th><th>Estado</th><th className="hide-sm">Requisições</th>{stoppable && <th><span className="sr-only">Ação</span></th>}</tr></thead>
        <tbody>{scans.map(scan => <tr key={scan.id}>
            <td className="mono scan-id">{scanLabel(scan)}</td>
            <td>{scan.owner}</td>
            <td className="muted hide-sm">{scan.host}</td>
            <td><div className="badge-stack"><Status status={scan.status} />{scan.result && outcomes[scan.result] && <Badge tone={outcomes[scan.result][1]}>{outcomes[scan.result][0]}</Badge>}</div></td>
            <td className="mono hide-sm nowrap">{scan.request_count}/{scan.budget} · {scan.blocked_count} barr.</td>
            {stoppable && <td className="cell-action"><ConfirmAction href={'/admin/sessoes/' + scan.id + '/encerrar'} title={'Encerrar ' + scanLabel(scan) + '?'} description={'A sessão de ' + scan.owner + ' para no próximo passo.'} confirmLabel="Encerrar sessão"><Square size={14} /> Encerrar</ConfirmAction></td>}
        </tr>)}</tbody>
    </table></div>;
}
const engineFields = ['provider', 'model', 'nav_model', 'api_key', 'daily_limit'];
function EngineForm({ engine }) {
    const form = useForm({ provider: engine.provider, model: engine.model ?? '', nav_model: engine.nav_model ?? '', api_key: '', daily_limit: engine.limit });
    const hosted = engine.hosted.includes(form.data.provider);
    const saved = form.data.provider === engine.provider && engine.keyHint;
    const options = { preserveScroll: true, preserveState: true };
    const save = event => { event.preventDefault(); form.put('/admin/motor', { ...options, onSuccess: () => form.reset('api_key') }); };
    return <form className="engine-form" onSubmit={save}>
        <div className="panel-body">
            <div className="engine-status">{engine.ready ? <Badge tone="green">Ativo para todas as contas</Badge> : <Badge>Desligado</Badge>}<span>{engine.ready ? 'Todas as sessões com IA usam este motor.' : 'Sem motor, as sessões rodam o roteiro do laboratório.'}</span></div>
            <div className="form-stack">
                <Field label="Provedor" error={form.errors.provider}><select value={form.data.provider} onChange={e => form.setData('provider', e.target.value)}>{Object.entries(engine.providers).map(([key, label]) => <option key={key} value={key}>{key === 'lab' ? 'Desligado (roteiro do laboratório)' : label}</option>)}</select></Field>
                {form.data.provider !== 'lab' && <Field label="Modelo estrategista" error={form.errors.model} help={hosted ? 'Modelo que pensa: planeja ataque, monta payload, decide escalada.' : 'Opcional no motor local.'}><input className="mono-input" value={form.data.model} onChange={e => form.setData('model', e.target.value)} placeholder={form.data.provider === 'anthropic' ? 'claude-sonnet-5-5' : ''} /></Field>}
                {hosted && <Field label="Modelo navegador" error={form.errors.nav_model} help="Modelo barato que navega e clica. Opcional — vazio usa o estrategista para tudo."><input className="mono-input" value={form.data.nav_model} onChange={e => form.setData('nav_model', e.target.value)} placeholder="claude-haiku-5-5" /></Field>}
                {hosted && <Field label="Chave de API" error={form.errors.api_key} help={saved ? 'Chave salva terminando em ' + engine.keyHint + '. Deixe vazio para manter.' : 'Fica criptografada no banco. Depois de salva, só aparece o final.'}><input type="password" autoComplete="new-password" className="mono-input" value={form.data.api_key} onChange={e => form.setData('api_key', e.target.value)} placeholder={saved ? '••••••••' + engine.keyHint.slice(1) : ''} /></Field>}
                <Field label="Limite diário por conta" error={form.errors.daily_limit} help="Sessões com IA por conta, por dia. Admins não têm limite."><input type="number" min={1} max={500} inputMode="numeric" value={form.data.daily_limit} onChange={e => form.setData('daily_limit', e.target.value)} /></Field>
            </div>
        </div>
        <div className="panel-foot">
            {form.data.provider !== 'lab' && <button type="button" className="button secondary" disabled={form.processing} onClick={() => form.post('/admin/motor/testar', options)}><PlugZap size={16} /> Testar conexão</button>}
            <button className="button primary" disabled={form.processing}><Check size={17} /> {form.processing ? 'Salvando…' : 'Salvar motor'}</button>
        </div>
    </form>;
}
export function Admin({ paused, stats, active, recent, users, horizon, engine }) {
    const { auth, errors } = usePage().props;
    const [tab, setTab] = useTab('aba', 'ativas', ['ativas', 'recentes', 'contas', 'achados', 'motor']);
    const levels = ['critical', 'high', 'medium', 'low'];
    return <Layout title="Super admin">
        <Heading title="Super admin" description="Sessões de todas as contas, parada de emergência e acesso.">
            {horizon && <a className="button secondary" href="/horizon"><Activity size={17} /> Fila Horizon</a>}
        </Heading>
        <section className={'panel kill-panel ' + (paused ? 'kill-paused' : '')}>
            <span className="kill-icon"><OctagonX size={20} /></span>
            <div className="kill-text"><h2>Controle de emergência</h2><p>{paused ? 'Novas sessões pausadas em toda a plataforma.' : 'Aceitando novas sessões.'} {plural(stats.active, 'sessão ativa', 'sessões ativas')} agora.</p></div>
            <div className="kill-actions">
                <Link href="/admin/pausa" method="post" data={{ paused: !paused }} as="button" preserveScroll className="button secondary">{paused ? <><Play size={16} /> Liberar novas sessões</> : <><Pause size={16} /> Pausar novas sessões</>}</Link>
                <ConfirmAction href="/admin/parar-tudo" className="button danger" title="Parar todas as sessões?" description="Todas as sessões ativas, de todas as contas, são encerradas agora." confirmLabel="Parar todas"><OctagonX size={16} /> Parar todas</ConfirmAction>
            </div>
        </section>
        <div className="metrics admin-metrics">
            {[['Contas', stats.users, Users], ['Ambientes verificados', stats.targets, Layers3], ['Sessões', stats.sessions, CirclePlay], ['Tentativas barradas', stats.blocked, LockKeyhole]].map(([label, value, Icon]) => <div key={label} className="metric">
                <span className="metric-icon"><Icon size={23} /></span><div><div className="metric-label">{label}</div><strong>{value}</strong></div>
            </div>)}
        </div>
        <section className="panel">
            <div className="panel-tabs"><Tabs name="admin" label="Seções" value={tab} onChange={setTab} tabs={[
                { key: 'ativas', label: 'Sessões ativas', count: active.length, tone: active.length ? 'violet' : '' },
                { key: 'recentes', label: 'Últimas sessões' },
                { key: 'contas', label: 'Contas', count: users.length },
                { key: 'achados', label: 'Achados' },
                { key: 'motor', label: 'Motor de IA', alert: engineFields.some(field => errors?.[field]) },
            ]} /></div>
            {tab === 'ativas' && <TabPanel name="admin" id="ativas"><AdminScans scans={active} stoppable /></TabPanel>}
            {tab === 'recentes' && <TabPanel name="admin" id="recentes"><AdminScans scans={recent} /></TabPanel>}
            {tab === 'contas' && <TabPanel name="admin" id="contas"><div className="table-scroll"><table className="data-table">
                <thead><tr><th>Conta</th><th className="hide-sm num">Sessões</th><th className="hide-sm num">Ambientes</th><th className="num">Achados</th><th>Estado</th><th><span className="sr-only">Ação</span></th></tr></thead>
                <tbody>{users.map(user => <tr key={user.id}>
                    <td><div className="cell-stack"><strong>{user.name}</strong><small>{user.email}</small></div></td>
                    <td className="hide-sm num">{user.scans_count}</td><td className="hide-sm num">{user.targets_count}</td><td className="num">{user.findings}</td>
                    <td>{user.is_admin ? <Badge tone="violet">Admin</Badge> : user.suspended_at ? <Badge tone="red">Suspensa</Badge> : <Badge tone="green">Ativa</Badge>}</td>
                    <td className="cell-action">{user.email !== auth.email && (user.suspended_at
                        ? <Link href={'/admin/usuarios/' + user.id + '/suspensao'} method="post" data={{ suspended: false }} as="button" preserveScroll className="button secondary compact"><Play size={14} /> Reativar</Link>
                        : <ConfirmAction href={'/admin/usuarios/' + user.id + '/suspensao'} data={{ suspended: true }} title={'Suspender ' + user.name + '?'} description="A conta perde o acesso e as sessões dela são encerradas." confirmLabel="Suspender conta"><UserX size={14} /> Suspender</ConfirmAction>)}</td>
                </tr>)}</tbody>
            </table></div></TabPanel>}
            {tab === 'motor' && <TabPanel name="admin" id="motor"><EngineForm engine={engine} /></TabPanel>}
            {tab === 'achados' && <TabPanel name="admin" id="achados" className="panel-body">
                <div className="severity-row">{levels.map(level => <div key={level} className={'severity-count ' + severities[level][1]}><strong>{stats.severity[level] ?? 0}</strong><span>{severities[level][0]}</span></div>)}</div>
            </TabPanel>}
        </section>
    </Layout>;
}
