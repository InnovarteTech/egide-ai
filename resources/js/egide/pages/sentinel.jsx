import { useEffect, useState } from 'react';
import { Link, useForm } from '@inertiajs/react';
import { Activity, ArrowDownToLine, ArrowLeft, ArrowRight, Check, ChevronRight, Info, LockKeyhole, Plus, Radio, RefreshCw, ShieldCheck, ShieldAlert, Trash2 } from 'lucide-react';
import { severities, formatDate, plural } from '../format';
import { Badge, useTab, Tabs, TabPanel, Dialog, ConfirmAction, CopyBox, Empty, Field } from '../ui';
import { Layout, Heading } from '../layout';

const eventTypes = {
    login_failed: ['Login recusado', 'red'],
    login_succeeded: ['Login aceito', 'green'],
    access_denied: ['Acesso negado', 'violet'],
    password_reset: ['Redefinição de senha', 'neutral'],
};
export function Monitors({ monitors }) {
    const [creating, setCreating] = useState(false);
    const form = useForm({ name: '' });
    return <Layout title="Sentinela">
        <Heading title="Sentinela" description="Alertas de login e acesso suspeito nas suas aplicações.">
            <button type="button" className="button primary" onClick={() => setCreating(true)}><Plus size={19} /> Novo monitor</button>
        </Heading>
        <section className="panel">
            <div className="panel-header"><div><h2>Aplicações monitoradas</h2><p>{plural(monitors.length, 'monitor', 'monitores')}</p></div></div>
            {!monitors.length && <Empty icon={Radio} title="Nenhum monitor criado" action={<button type="button" className="text-link" onClick={() => setCreating(true)}>Criar o primeiro monitor <ArrowRight size={16} /></button>}>Crie um monitor e instale o SDK no backend da sua aplicação.</Empty>}
            <ul className="asset-list">{monitors.map(monitor => <li key={monitor.id}><Link href={'/sentinela/' + monitor.id} className="asset-row monitor-row">
                <div className="asset-head">
                    <span className={'asset-icon ' + (monitor.open_alerts ? 'is-alert' : 'is-verified')}><Radio size={19} /></span>
                    <div className="asset-main"><h3>{monitor.name}</h3><p className="mono">{monitor.key_prefix}… · {plural(monitor.events_24h, 'evento', 'eventos')} em 24h · último {formatDate(monitor.last_event_at)}</p></div>
                    <div className="asset-tags"><Badge tone={monitor.open_alerts ? 'red' : 'green'}>{monitor.open_alerts ? plural(monitor.open_alerts, 'alerta aberto', 'alertas abertos') : 'Sem alertas'}</Badge><ChevronRight size={18} className="row-chevron" /></div>
                </div>
            </Link></li>)}</ul>
        </section>
        <Dialog open={creating} onClose={() => setCreating(false)} title="Novo monitor" description="Cada aplicação recebe uma chave própria." size="dialog-sm" footer={<>
            <button type="button" className="button secondary" onClick={() => setCreating(false)}>Cancelar</button>
            <button type="submit" form="monitor-form" className="button primary" disabled={form.processing}>{form.processing ? 'Criando…' : 'Criar monitor'} <ArrowRight size={17} /></button>
        </>}>
            <form id="monitor-form" className="form-stack" onSubmit={e => { e.preventDefault(); form.post('/sentinela', { preserveState: 'errors' }); }}>
                <Field label="Nome da aplicação" error={form.errors.name}><input required data-autofocus value={form.data.name} onChange={e => form.setData('name', e.target.value)} placeholder="Agenda+ produção" /></Field>
                <p className="form-note"><LockKeyhole size={16} /><span>O SDK envia só IP, rota, status e um hash do usuário. E-mail e senha não saem da sua aplicação.</span></p>
            </form>
        </Dialog>
    </Layout>;
}
export function MonitorPage({ monitor, issuedKey: issued, endpoint, stats, alerts, events }) {
    const [tab, setTab] = useTab('aba', 'alertas', ['alertas', 'eventos', 'instalacao', 'config']);
    const [stack, setStack] = useState('express');
    const [keyOpen, setKeyOpen] = useState(!!issued);
    useEffect(() => { if (issued) setKeyOpen(true); }, [issued]);
    const form = useForm({ name: monitor.name, webhook_url: '' });
    const snippets = {
        express: `import { sentinela } from './egide-sentinela.mjs';\n\napp.set('trust proxy', 1);\napp.use(sentinela({\n  key: process.env.EGIDE_SENTINELA_KEY,\n  endpoint: '${endpoint}',\n  loginPaths: ['/api/auth/login'],\n}));`,
        laravel: `// app/Providers/AppServiceProvider.php → boot()\nuse Illuminate\\Auth\\Events\\{Failed, Login};\nuse Illuminate\\Support\\Facades\\{Event, Http};\n\n$send = function (string $type, ?string $user) {\n    $key = config('services.egide.key');\n    app()->terminating(fn () => rescue(fn () => Http::timeout(2)->withToken($key)\n        ->post(config('services.egide.endpoint'), ['events' => [[\n            'type' => $type, 'ip' => request()->ip(), 'path' => '/'.request()->path(),\n            'subject' => $user ? hash_hmac('sha256', strtolower(trim($user)), $key) : null,\n        ]]]), report: false));\n};\nEvent::listen(Failed::class, fn ($e) => $send('login_failed', $e->credentials['email'] ?? null));\nEvent::listen(Login::class, fn ($e) => $send('login_succeeded', $e->user->email));`,
        http: `curl -X POST ${endpoint} \\\n  -H "Authorization: Bearer esc_SUA_CHAVE" -H "Content-Type: application/json" \\\n  -d '{"events":[{"type":"login_failed","ip":"203.0.113.7","path":"/login","status":401}]}'`,
    };
    const open = alerts.filter(alert => alert.status === 'open').length;
    return <Layout title={monitor.name}>
        <Link className="back-link" href="/sentinela"><ArrowLeft size={16} /> Monitores</Link>
        <Heading title={monitor.name} description={'Chave ' + monitor.key_prefix + '… · ' + plural(stats.ips, 'IP observado', 'IPs observados') + ' em 24h'} />
        <div className="metrics monitor-metrics">
            {[['Eventos em 24h', stats.events, Activity], ['Logins recusados', stats.failed, LockKeyhole], ['Acessos negados', stats.denied, ShieldAlert], ['Alertas abertos', stats.open, Radio]].map(([label, value, Icon]) => <div key={label} className="metric">
                <span className="metric-icon"><Icon size={23} /></span><div><div className="metric-label">{label}</div><strong>{value}</strong></div>
            </div>)}
        </div>
        <Tabs name="monitor" label="Seções do monitor" value={tab} onChange={setTab} className="page-tabs" tabs={[
            { key: 'alertas', label: 'Alertas', count: open, tone: open ? 'red' : '' },
            { key: 'eventos', label: 'Eventos', count: events.length },
            { key: 'instalacao', label: 'Instalação' },
            { key: 'config', label: 'Configurações', alert: !!(form.errors.name || form.errors.webhook_url) },
        ]} />
        {tab === 'alertas' && <TabPanel name="monitor" id="alertas"><section className="panel">
            {!alerts.length && <Empty icon={ShieldCheck} title="Nenhum alerta">As regras de detecção avaliam cada lote de eventos recebido.</Empty>}
            <ul className="alert-list">{alerts.map(alert => <li key={alert.id} className={'alert-row ' + (alert.status === 'open' ? '' : 'alert-resolved')}>
                <span className={'asset-icon ' + (alert.status === 'open' ? 'is-alert' : '')}><ShieldAlert size={18} /></span>
                <div className="alert-main">
                    <div className="alert-title"><h3>{alert.title}</h3><Badge tone={severities[alert.severity]?.[1] ?? 'neutral'}>{severities[alert.severity]?.[0] ?? alert.severity}</Badge>{alert.status !== 'open' && <Badge tone="green">Tratado</Badge>}</div>
                    <p>{alert.detail}</p>
                    <small className="mono">{formatDate(alert.first_seen_at)} → {formatDate(alert.last_seen_at)} · {plural(alert.count, 'ocorrência', 'ocorrências')}{alert.ip ? ' · ' + alert.ip : ''}</small>
                </div>
                <Link href={'/alertas/' + alert.id + '/status'} method="post" as="button" preserveScroll className="button secondary compact">{alert.status === 'open' ? <><Check size={14} /> Marcar como tratado</> : <><RefreshCw size={14} /> Reabrir</>}</Link>
            </li>)}</ul>
        </section></TabPanel>}
        {tab === 'eventos' && <TabPanel name="monitor" id="eventos"><section className="panel">
            {!events.length ? <Empty icon={Activity} title="Aguardando o primeiro evento" action={<button type="button" className="text-link" onClick={() => setTab('instalacao')}>Ver instalação <ArrowRight size={16} /></button>}>Instale o SDK e faça um login na aplicação.</Empty>
                : <div className="table-scroll"><table className="data-table"><thead><tr><th>Horário</th><th>Evento</th><th>IP</th><th className="hide-sm">Rota</th><th className="hide-sm">Usuário (hash)</th></tr></thead><tbody>
                    {events.map(event => <tr key={event.id}><td className="mono nowrap muted">{formatDate(event.occurred_at)}</td><td><Badge tone={eventTypes[event.type]?.[1]}>{eventTypes[event.type]?.[0] ?? event.type}</Badge></td><td className="mono">{event.ip}</td><td className="mono hide-sm">{event.path ?? '—'}{event.status ? ' · ' + event.status : ''}</td><td className="mono hide-sm muted">{event.subject ? event.subject + '…' : '—'}</td></tr>)}
                </tbody></table></div>}
        </section></TabPanel>}
        {tab === 'instalacao' && <TabPanel name="monitor" id="instalacao"><section className="panel">
            <div className="panel-header"><div><h2>Instalação</h2><p>Envie os eventos de login do backend da sua aplicação.</p></div><a className="button secondary compact" href="/sdk/egide-sentinela.mjs" download><ArrowDownToLine size={15} /> SDK Express</a></div>
            <div className="panel-body">
                <div className="segmented" role="group" aria-label="Tecnologia">
                    {[['express', 'Node.js · Express'], ['laravel', 'Laravel'], ['http', 'HTTP']].map(([value, label]) => <button key={value} type="button" aria-pressed={stack === value} onClick={() => setStack(value)}>{label}</button>)}
                </div>
                <pre className="code-block">{snippets[stack]}</pre>
                <p className="form-note"><Info size={16} /><span>O campo <code>subject</code> precisa ser um HMAC-SHA256 do usuário em hexadecimal. E-mails em texto puro são recusados.</span></p>
            </div>
        </section></TabPanel>}
        {tab === 'config' && <TabPanel name="monitor" id="config" className="stack">
            <form className="panel narrow" onSubmit={e => { e.preventDefault(); form.put('/sentinela/' + monitor.id, { preserveScroll: true, preserveState: true, onSuccess: () => form.reset('webhook_url') }); }}>
                <div className="panel-header"><div><h2>Notificações</h2><p>Para onde enviar cada alerta novo.</p></div>{monitor.has_webhook && <Badge tone="green">Webhook ativo</Badge>}</div>
                <div className="panel-body form-stack">
                    <Field label="Nome" error={form.errors.name}><input required value={form.data.name} onChange={e => form.setData('name', e.target.value)} /></Field>
                    <Field label="Webhook de alerta (HTTPS)" error={form.errors.webhook_url} help={monitor.has_webhook ? 'Salve vazio para remover o webhook atual.' : 'Slack, Discord, n8n ou qualquer URL que receba JSON.'}><input type="url" value={form.data.webhook_url} onChange={e => form.setData('webhook_url', e.target.value)} placeholder="https://hooks.slack.com/services/…" /></Field>
                </div>
                <div className="panel-foot"><button className="button primary" disabled={form.processing}><Check size={17} /> Salvar</button></div>
            </form>
            <section className="panel narrow danger-zone">
                <div className="panel-header"><div><h2>Chave e remoção</h2><p>Ações que afetam a coleta imediatamente.</p></div></div>
                <div className="danger-row"><div><strong>Gerar nova chave</strong><p>A chave atual para de funcionar na hora.</p></div><ConfirmAction href={'/sentinela/' + monitor.id + '/chave'} title="Gerar nova chave?" description="A chave atual para de funcionar na hora. Atualize EGIDE_SENTINELA_KEY na aplicação." confirmLabel="Gerar nova chave" tone="primary"><RefreshCw size={14} /> Gerar chave</ConfirmAction></div>
                <div className="danger-row"><div><strong>Remover monitor</strong><p>Apaga eventos e alertas deste monitor.</p></div><ConfirmAction href={'/sentinela/' + monitor.id} method="delete" className="button danger-outline compact" title={'Remover ' + monitor.name + '?'} description="O monitor, os eventos e os alertas são apagados. Não dá para desfazer." confirmLabel="Remover monitor"><Trash2 size={14} /> Remover</ConfirmAction></div>
            </section>
        </TabPanel>}
        <Dialog open={keyOpen && !!issued} onClose={() => setKeyOpen(false)} title="Chave de ingestão" description="Guarde em EGIDE_SENTINELA_KEY. Ela não será exibida novamente." footer={<button type="button" className="button primary" onClick={() => setKeyOpen(false)} data-autofocus><Check size={16} /> Já guardei</button>}>
            {issued && <CopyBox value={issued} />}
        </Dialog>
    </Layout>;
}
