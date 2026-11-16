import { useEffect, useState } from 'react';
import { Link, router, useForm } from '@inertiajs/react';
import { Activity, ArrowDownToLine, ArrowLeft, ArrowRight, ArrowUpRight, Check, CirclePlay, Crosshair, Fingerprint, Globe2, LockKeyhole, Monitor, Plus, Radio, RefreshCw, ShieldCheck, Printer, Square, TriangleAlert, X } from 'lucide-react';
import { outcomes, captureAge, formatDate, formatTime, scanLabel, hostOf, plural, bySeverity } from '../format';
import { Badge, Status, useTab, Tabs, TabPanel, Empty, Pagination } from '../ui';
import { Layout, Heading } from '../layout';
import { RuleColumns, FindingCard, Observations, ScanResult } from '../evidence';

export function Sessions({ scans, filter = 'todas', counts = {} }) {
    const change = key => router.get('/sessoes', key === 'todas' ? {} : { filtro: key }, { preserveState: true, preserveScroll: true, replace: true });
    const empty = {
        todas: ['Nenhuma sessão registrada', 'Execute o laboratório para acompanhar sua primeira avaliação.'],
        ativas: ['Nenhuma sessão em andamento', 'As sessões na fila ou em execução aparecem aqui.'],
        achados: ['Nenhuma sessão com achados', 'Sessões com falha confirmada aparecem aqui.'],
    }[filter];
    return <Layout title="Sessões">
        <Heading title="Sessões" description="Avaliações em andamento e histórico."><Link href="/sessoes/nova" className="button primary"><Plus size={19} /> Nova sessão</Link></Heading>
        <section className="panel">
            <div className="panel-tabs"><Tabs name="sessoes" label="Filtrar sessões" value={filter} onChange={change} tabs={[
                { key: 'todas', label: 'Todas', count: counts.todas },
                { key: 'ativas', label: 'Em andamento', count: counts.ativas, tone: counts.ativas ? 'violet' : '' },
                { key: 'achados', label: 'Com achados', count: counts.achados, tone: counts.achados ? 'red' : '' },
            ]} /></div>
            <TabPanel name="sessoes" id={filter}>
                {!scans.data.length ? <Empty icon={CirclePlay} title={empty[0]} action={filter === 'todas' && <Link href="/sessoes/nova" className="text-link">Configurar uma sessão <ArrowRight size={16} /></Link>}>{empty[1]}</Empty>
                    : <div className="table-scroll"><table className="data-table">
                        <thead><tr><th>Sessão</th><th>Ambiente</th><th className="hide-sm">Início</th><th>Resultado</th><th className="hide-sm num">Achados</th><th className="hide-sm"><span className="sr-only">Abrir</span></th></tr></thead>
                        <tbody>{scans.data.map(scan => <tr key={scan.id}>
                            <td><Link href={'/sessoes/' + scan.id} className="mono scan-id">{scanLabel(scan)}</Link></td>
                            <td><div className="cell-stack"><span>{scan.name}</span><small className="mono hide-sm">{hostOf(scan.scope?.url)}</small></div></td>
                            <td className="hide-sm muted nowrap">{formatDate(scan.created_at)}</td>
                            <td><ScanResult scan={scan} /></td>
                            <td className="hide-sm num">{scan.findings_count ? <strong className="count-red">{scan.findings_count}</strong> : <span className="muted">0</span>}</td>
                            <td className="cell-action hide-sm"><Link href={'/sessoes/' + scan.id} className="icon-button" aria-label={'Abrir ' + scanLabel(scan)}><ArrowUpRight size={17} /></Link></td>
                        </tr>)}</tbody>
                    </table></div>}
                <Pagination links={scans.links} />
            </TabPanel>
        </section>
    </Layout>;
}
const eventIcons = { browser: Monitor, identity: Fingerprint, network: Globe2, blocked: LockKeyhole, finding: Crosshair, verified: Check, test: Activity, error: X, system: Radio };
export function Session(initial) {
    const [state, setState] = useState(initial);
    const { scan, events, findings, observations = [], frame, frame_at: frameAt } = state;
    const active = ['queued', 'running'].includes(scan.status);
    const base = '/sessoes/' + scan.id;
    const outcome = outcomes[scan.result];
    const stop = useForm({});
    const [connectionError, setConnectionError] = useState(false);
    const hasResult = !!outcome || findings.length > 0 || observations.length > 0;
    const [tab, setTab] = useTab('aba', !active && hasResult ? 'resultado' : 'execucao', ['execucao', 'resultado', 'rede', 'escopo']);

    useEffect(() => {
        if (!active) return;
        const controller = new AbortController();
        let timer;
        const poll = async () => {
            try {
                const response = await fetch(base + '/eventos', { signal: controller.signal, headers: { Accept: 'application/json' }, cache: 'no-store' });
                if (!response.ok) throw new Error();
                setState(await response.json());
                setConnectionError(false);
            } catch {
                if (!controller.signal.aborted) setConnectionError(true);
            }
            if (!controller.signal.aborted) timer = setTimeout(poll, 1300);
        };
        timer = setTimeout(poll, 500);
        return () => { controller.abort(); clearTimeout(timer); };
    }, [base, active]);

    const activity = events.filter(event => !['network', 'blocked'].includes(event.type)).slice().reverse();
    const network = events.filter(event => ['network', 'blocked'].includes(event.type)).slice().reverse();
    const used = Math.min(100, Math.round((scan.request_count / Math.max(scan.budget, 1)) * 100));
    const host = hostOf(scan.scope.url);

    return <Layout title="Sessão">
        <Link className="back-link" href="/sessoes"><ArrowLeft size={16} /> Todas as sessões</Link>
        <Heading title={scan.name} description={scanLabel(scan) + '  ·  ' + host}>
            {active ? <button type="button" className="button secondary" disabled={stop.processing || !!scan.stop_requested_at} onClick={() => stop.post(base + '/encerrar', { preserveScroll: true, preserveState: true })}><Square size={15} /> {scan.stop_requested_at ? 'Encerrando…' : 'Encerrar'}</button>
                : <><Link className="button secondary" href={base + '/relatorio/imprimir'}><Printer size={17} /> Relatório</Link><a className="button secondary" href={base + '/relatorio'}><ArrowDownToLine size={17} /> JSON</a></>}
            {scan.result === 'exposure' && <Link href={scan.mode === 'external' ? '/sessoes/nova?mode=external&retest=' + scan.id : '/sessoes/nova?mode=retest' + (scan.provider !== 'lab' ? '&agent=1' : '')} className="button primary"><RefreshCw size={17} /> Rodar reteste</Link>}
        </Heading>
        {scan.error && <div className="notice error-notice" role="alert"><TriangleAlert size={16} />{scan.error}</div>}
        {connectionError && <div className="notice" role="status"><RefreshCw size={16} />Reconectando à atividade da sessão…</div>}
        <dl className="stat-strip panel">
            <div><dt>Estado</dt><dd><Status status={scan.status} /></dd></div>
            <div><dt>Etapa</dt><dd>{scan.phase}</dd></div>
            <div><dt>Endpoints</dt><dd>{scan.endpoint_count}</dd></div>
            <div><dt>Bloqueios</dt><dd>{scan.blocked_count}</dd></div>
            <div><dt>Requisições</dt><dd>{scan.request_count}<small> / {scan.budget}</small><span className="mini-bar" role="progressbar" aria-label="Requisições usadas" aria-valuenow={used} aria-valuemin="0" aria-valuemax="100"><i style={{ width: used + '%' }} /></span></dd></div>
        </dl>
        <Tabs name="sessao" label="Seções da sessão" value={tab} onChange={setTab} className="page-tabs" tabs={[
            { key: 'execucao', label: active ? 'Ao vivo' : 'Execução', icon: Monitor },
            { key: 'resultado', label: 'Resultado', icon: Crosshair, count: findings.length || undefined, tone: findings.length ? 'red' : '' },
            { key: 'rede', label: 'Rede', icon: Globe2, count: network.length },
            { key: 'escopo', label: 'Escopo', icon: ShieldCheck },
        ]} />
        {tab === 'execucao' && <TabPanel name="sessao" id="execucao" className="session-columns">
            <section className="panel browser-panel">
                <div className="panel-header"><h2>Firefox</h2><Badge tone={scan.status === 'running' ? 'green' : 'neutral'}>{scan.status === 'running' ? 'Captura automática' : frame ? 'Última captura' : 'Em espera'}</Badge></div>
                <div className="browser-view">
                    {frame ? <img alt="Captura da sessão no Firefox" src={base + '/imagem?v=' + encodeURIComponent(events.at(-1)?.id ?? scan.updated_at)} />
                        : <div className="browser-placeholder"><Monitor size={36} strokeWidth={1.4} /><strong>{active ? 'Aguardando o Firefox' : 'Captura indisponível'}</strong><span>A imagem aparece quando o executor carrega a página.</span></div>}
                    {active && frame && frameAt && <span className="frame-stamp">Capturado {captureAge(frameAt)}</span>}
                </div>
                <div className="browser-foot"><LockKeyhole size={15} /> {host}<span>{scan.mode === 'external' ? 'Ambiente verificado' : 'Laboratório'}</span></div>
            </section>
            <section className="panel timeline-panel">
                <div className="panel-header"><h2>Atividade</h2>{active && <span className="live-dot">Atualizando</span>}</div>
                <ol className="timeline">{activity.map(event => {
                    const Icon = eventIcons[event.type] ?? Activity;
                    return <li key={event.id} className={'timeline-event event-' + event.type}>
                        <span className="event-icon"><Icon size={15} /></span>
                        <div><div className="event-top"><strong>{event.title}</strong><time dateTime={event.created_at}>{formatTime(event.created_at)}</time></div>{event.detail && <p>{event.detail}</p>}</div>
                    </li>;
                })}{!activity.length && <li className="timeline-empty">As decisões e verificações aparecem aqui.</li>}</ol>
            </section>
        </TabPanel>}
        {tab === 'resultado' && <TabPanel name="sessao" id="resultado" className="stack">
            <section className="panel">
                <div className="panel-header"><h2>Resultado da avaliação</h2>{outcome && <Badge tone={outcome[1]}>{outcome[0]}</Badge>}</div>
                {!hasResult && <Empty icon={Crosshair} title={active ? 'Sessão em andamento' : 'Sem resultado'}>{active ? 'O resultado aparece quando a prova terminar.' : 'A sessão terminou sem um veredito.'}</Empty>}
                {bySeverity(findings).map(finding => <FindingCard key={finding.id} finding={finding} />)}
                {scan.result === 'protected' && <p className="result-text">A aplicação negou o acesso cruzado na rota testada. As duas contas continuaram acessando seus próprios registros.</p>}
                {scan.result === 'inconclusive' && <p className="result-text">A prova não reuniu evidência suficiente. Confira a atividade registrada na aba Execução.</p>}
                {scan.result === 'mapped' && <p className="result-text">O relatório reúne as rotas e ações observadas durante a exploração.</p>}
                {scan.result === 'challenge' && <p className="result-text">A execução chegou a uma verificação humana no ambiente autorizado.</p>}
                {scan.scope.retest_of && <div className="panel-foot start"><Link href={'/sessoes/' + scan.scope.retest_of} className="text-link">Ver a sessão original <ArrowRight size={16} /></Link></div>}
            </section>
            <Observations observations={observations} />
        </TabPanel>}
        {tab === 'rede' && <TabPanel name="sessao" id="rede">
            <section className="panel">
                <div className="panel-header"><div><h2>Chamadas observadas</h2><p>{plural(scan.request_count, 'requisição', 'requisições')} · {plural(scan.blocked_count, 'barrada', 'barradas')} pelo escopo</p></div></div>
                {!network.length ? <Empty icon={Globe2} title="Nenhuma chamada ainda">As requisições aparecem conforme o Firefox navega.</Empty>
                    : <div className="table-scroll network-scroll"><table className="data-table">
                        <thead><tr><th>Horário</th><th>Requisição</th><th>Resposta</th></tr></thead>
                        <tbody>{network.map(event => <tr key={event.id} className={event.type === 'blocked' ? 'row-blocked' : ''}>
                            <td className="mono muted nowrap">{formatTime(event.created_at)}</td>
                            <td><code className="request">{event.title}</code>{event.type === 'blocked' && event.detail && <small className="row-note">{event.detail}</small>}</td>
                            <td className="nowrap">{event.type === 'blocked' ? <Badge tone="red">Barrada</Badge> : <span className={'http-status ' + ((event.data?.status ?? 0) >= 400 ? 'is-error' : '')}>{event.data?.status ?? '—'}</span>}</td>
                        </tr>)}</tbody>
                    </table></div>}
            </section>
        </TabPanel>}
        {tab === 'escopo' && <TabPanel name="sessao" id="escopo">
            <section className="panel">
                <div className="panel-header"><div><h2>Regras da sessão</h2><p>Impostas pelo proxy do executor, fora do controle da IA.</p></div></div>
                <div className="panel-body"><RuleColumns scope={scan.scope} /></div>
                <div className="budget-row">
                    <div><strong>{scan.request_count} / {scan.budget}</strong><span>requisições usadas</span></div>
                    <div className="budget-bar" role="progressbar" aria-valuenow={used} aria-valuemin="0" aria-valuemax="100" aria-label="Requisições usadas"><i style={{ width: used + '%' }} /></div>
                </div>
            </section>
        </TabPanel>}
    </Layout>;
}
