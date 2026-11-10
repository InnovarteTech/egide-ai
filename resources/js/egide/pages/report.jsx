import { Head, Link } from '@inertiajs/react';
import { ArrowLeft, Info, ShieldCheck, Printer, TriangleAlert } from 'lucide-react';
import { statuses, outcomes, severities, risks, verdicts, formatDate, formatTime, scanLabel, hostOf, bySeverity } from '../format';
import { Logo, Badge } from '../ui';
import { RuleColumns, crossAccount, evidenceFacts } from '../evidence';

const sensitiveFiles = ['.env', '.git/HEAD', '.git/config', 'backup.sql', 'dump.sql', 'phpinfo.php', 'server-status', 'actuator/env', '.DS_Store'];
const coverageTones = { falha: 'red', protegido: 'green', nao_testado: 'neutral' };
const coverageLabels = { falha: 'Falha', protegido: 'Protegido', nao_testado: 'Não testado' };
const cvssScores = { critical: '9.8', high: '7.5', medium: '5.3', low: '3.1' };
export function Report({ scan, events, findings, target, engine, generatedAt }) {
    const outcome = outcomes[scan.result];
    const status = statuses[scan.status] ?? [scan.status, 'neutral'];
    const blocked = events.filter(event => event.type === 'blocked');
    const network = events.filter(event => event.type === 'network');
    const probe = event => sensitiveFiles.some(file => event.title.endsWith('/' + file));
    const answered = event => (event.data?.status ?? 0) >= 100 && event.data.status < 400;
    const endpoints = [...new Set(network.filter(event => answered(event) && !probe(event)).map(event => event.title))];
    const absent = [...new Map(network.filter(event => (event.data?.status ?? 0) >= 400 || probe(event)).map(event => [event.title, event.data?.status])).entries()];
    const activity = events.filter(event => !['network', 'blocked'].includes(event.type));
    const host = hostOf(scan.scope.url);
    const coverage = scan.coverage ?? [];
    const coverageByCheck = coverage.reduce((groups, row) => ({ ...groups, [row.check]: [...(groups[row.check] ?? []), row] }), {});
    const tone = outcome?.[1] ?? 'neutral';
    const VerdictIcon = tone === 'red' ? TriangleAlert : tone === 'green' ? ShieldCheck : Info;
    return <div className="report">
        <Head title={'Relatório ' + scanLabel(scan)} />
        <div className="report-actions">
            <Link href={'/sessoes/' + scan.id} className="button secondary"><ArrowLeft size={16} /> Voltar à sessão</Link>
            <button type="button" className="button primary" onClick={() => window.print()}><Printer size={17} /> Imprimir ou salvar PDF</button>
        </div>
        <article className="report-page">
            <header className="report-head">
                <Logo />
                <div><h1>{scan.name}</h1><p>Relatório de avaliação autorizada · <span className="mono">{scanLabel(scan)} · {host}</span></p></div>
            </header>
            <dl className="report-meta">
                <div><dt>Ambiente</dt><dd>{target ? target.name + ' · ' + target.origin : 'Laboratório controlado'}</dd></div>
                <div><dt>Início</dt><dd>{formatDate(scan.started_at)}</dd></div>
                <div><dt>Término</dt><dd>{formatDate(scan.finished_at)}</dd></div>
                <div><dt>Motor de decisão</dt><dd>{engine}{scan.model ? ' · ' + scan.model : ''}</dd></div>
                <div><dt>Estado</dt><dd>{status[0]}</dd></div>
                <div><dt>Requisições</dt><dd>{scan.request_count} de {scan.budget} · {scan.blocked_count} barradas</dd></div>
            </dl>

            <section className="report-section">
                <h2>Resumo executivo</h2>
                <div className={'verdict ' + tone}>
                    <span className="verdict-icon"><VerdictIcon size={20} /></span>
                    <div>
                        <strong>{outcome?.[0] ?? status[0]}</strong>
                        <p>{verdicts[scan.result] ?? scan.error ?? 'A sessão terminou sem um veredito.'}</p>
                        {findings.some(item => item.evidence.kind) && <p>A varredura de configuração registrou {findings.filter(item => item.evidence.kind).length} ponto(s) adicional(is) com correção recomendada, listados por severidade abaixo.</p>}
                    </div>
                </div>
                {scan.summary && <div className="ai-summary">
                    <div className="ai-summary-head"><div><h3>Análise da IA</h3><small>Baseada somente nas evidências deste relatório.</small></div><Badge tone={risks[scan.summary.risk]?.[1] ?? 'neutral'}>Risco {risks[scan.summary.risk]?.[0] ?? scan.summary.risk}</Badge></div>
                    <p>{scan.summary.summary}</p>
                    {scan.summary.priorities?.length > 0 && <><h4>O que corrigir primeiro</h4><ol>{scan.summary.priorities.map(item => <li key={item}>{item}</li>)}</ol></>}
                </div>}
            </section>

            <section className="report-section">
                <h2>Escopo autorizado</h2>
                <p>Regras impostas pelo proxy do executor. Requisições fora delas foram barradas antes de sair do ambiente isolado.</p>
                <RuleColumns scope={scan.scope} />
            </section>

            <section className="report-section">
                <h2>Achados</h2>
                {findings.length > 0 && <div className="severity-row">{['critical', 'high', 'medium', 'low'].map(level => <div key={level} className={'severity-count ' + severities[level][1]}><strong>{findings.filter(item => item.severity === level).length}</strong><span>{severities[level][0]}</span></div>)}</div>}
                {findings.length ? bySeverity(findings).map(finding => {
                    const [severity, findingTone] = severities[finding.severity] ?? [finding.severity, 'neutral'];
                    const evidence = finding.evidence;
                    return <div className="report-finding" key={finding.id}>
                        <div className="finding-head"><h3>{finding.title}</h3><Badge tone={findingTone}>{severity}{cvssScores[finding.severity] ? ' · CVSS ' + cvssScores[finding.severity] : ''}</Badge></div>
                        <p className="muted">{finding.category}</p>
                        <table className="report-table"><tbody>
                            <tr><th>Requisição</th><td><code>{evidence.method} {evidence.path}</code></td></tr>
                            {evidence.kind ? <>
                                {evidence.paths?.length > 1 && <tr><th>Outras rotas</th><td>{evidence.paths.slice(1).map(path => <code key={path} className="inline-route">{path}</code>)}</td></tr>}
                                <tr><th>Evidência</th><td>{evidence.detail}</td></tr>
                            </> : crossAccount(evidence) ? <>
                                <tr><th>Sessão usada</th><td>{evidence.actor}</td></tr>
                                <tr><th>Dono do registro</th><td>{evidence.owner}</td></tr>
                                <tr><th>Controle positivo</th><td>HTTP {evidence.own_status} no registro próprio</td></tr>
                                <tr><th>Acesso cruzado</th><td>HTTP {evidence.cross_status}, marcador do outro registro presente na resposta</td></tr>
                            </> : <>
                                {evidenceFacts(evidence).map(([key, label, value]) => <tr key={key}><th>{label}</th><td>{value}</td></tr>)}
                                {evidence.detail && <tr><th>Evidência</th><td>{evidence.detail}</td></tr>}
                            </>}
                            {evidence.reference && <tr><th>Referência</th><td>{evidence.reference}</td></tr>}
                        </tbody></table>
                        <h4>Correção recomendada</h4>
                        <p>{finding.remediation}</p>
                        {!evidence.kind && <><h4>Como validar a correção</h4><p>{crossAccount(evidence)
                            ? 'Rode o reteste na Égide AI. A mesma prova precisa receber HTTP 403 ou 404 no acesso cruzado, mantendo o acesso de cada conta ao próprio registro.'
                            : 'Rode o reteste na Égide AI. A mesma verificação precisa terminar como protegida, sem reproduzir a prova acima.'}</p></>}
                    </div>;
                }) : <p>Nenhuma vulnerabilidade confirmada nesta sessão.</p>}
            </section>

            {coverage.length > 0 && <section className="report-section">
                <h2>Mapa de cobertura</h2>
                <p>O que a Égide testou nesta sessão, por classe de verificação e rota. "Não testado" é distinto de "protegido": não testado significa que a rota não pôde ser provada, não que é segura.</p>
                <table className="report-table"><thead><tr><th>Verificação</th><th>Falhas</th><th>Protegidas</th><th>Não testadas</th></tr></thead><tbody>
                    {Object.entries(coverageByCheck).map(([check, rows]) => <tr key={check}>
                        <td>{check}</td>
                        <td>{rows.filter(row => row.verdict === 'falha').length}</td>
                        <td>{rows.filter(row => row.verdict === 'protegido').length}</td>
                        <td>{rows.filter(row => row.verdict === 'nao_testado').length}</td>
                    </tr>)}
                </tbody></table>
                <ul className="endpoint-list">{coverage.map((row, index) => <li key={index}><code>{row.route}</code> · {row.check} · <Badge tone={coverageTones[row.verdict] ?? 'neutral'}>{coverageLabels[row.verdict] ?? row.verdict}</Badge></li>)}</ul>
            </section>}

            {endpoints.length > 0 && <section className="report-section">
                <h2>Superfície observada</h2>
                <ul className="endpoint-list">{endpoints.map(endpoint => <li key={endpoint}><code>{endpoint}</code></li>)}</ul>
            </section>}

            {absent.length > 0 && <section className="report-section">
                <h2>Caminhos verificados sem exposição</h2>
                <p>Arquivos sensíveis consultados dentro do escopo que não devolveram o conteúdo procurado. Servem como controle negativo da varredura.</p>
                <ul className="endpoint-list">{absent.map(([request, code]) => <li key={request}><code>{request} · HTTP {code}{code < 400 ? ' sem conteúdo sensível' : ''}</code></li>)}</ul>
            </section>}

            {blocked.length > 0 && <section className="report-section">
                <h2>Tentativas barradas pelo escopo</h2>
                <table className="report-table"><thead><tr><th>Horário</th><th>Requisição</th><th>Motivo</th></tr></thead><tbody>
                    {blocked.map(event => <tr key={event.id}><td className="mono">{formatTime(event.created_at)}</td><td><code>{event.title}</code></td><td>{event.detail}</td></tr>)}
                </tbody></table>
            </section>}

            <section className="report-section">
                <h2>Trilha de auditoria</h2>
                <ol className="report-timeline">{activity.map(event => <li key={event.id}><time className="mono">{formatTime(event.created_at)}</time><div><strong>{event.title}</strong>{event.detail && <p>{event.detail}</p>}</div></li>)}</ol>
            </section>

            <footer className="report-foot">Gerado pela Égide AI em {formatDate(generatedAt)}. Testes executados apenas no escopo autorizado, com dados sintéticos e identidades de teste.</footer>
        </article>
    </div>;
}
