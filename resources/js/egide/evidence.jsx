import { Link } from '@inertiajs/react';
import { Check, ChevronRight, Crosshair, X } from 'lucide-react';
import { outcomes, severities, ruleLabel, scanLabel } from './format';
import { Badge, Status } from './ui';

export function RuleColumns({ scope }) {
    return <div className="rule-columns">
        <div><h3>Permitido</h3><ul className="rule-list">{(scope.rules ?? []).map(rule => <li key={ruleLabel(rule)}><Check size={14} /><code>{ruleLabel(rule)}</code></li>)}</ul></div>
        <div><h3>Bloqueado</h3><ul className="rule-list denied">{(scope.denied ?? []).map(path => <li key={path}><X size={14} /><code>{path}/*</code></li>)}
            <li><X size={14} /><span>Outros domínios, métodos e rotas</span></li></ul></div>
    </div>;
}
const factLabels = [
    ['actor', 'Sessão'], ['owner', 'Proprietária'], ['field', 'Campo'], ['probed_id', 'ID testado'],
    ['payload', 'Carga'], ['probe', 'Carga'], ['rounds', 'Rodadas'], ['true_status', 'HTTP com condição verdadeira'],
    ['false_status', 'HTTP com condição falsa'], ['redirect_host', 'Destino do redirecionamento'], ['status', 'HTTP'],
    ['baseline_ms', 'Tempo base (ms)'], ['payload_ms', 'Tempo com a carga (ms)'], ['anon_status', 'HTTP sem sessão'],
    ['normal_status', 'HTTP da conta comum'], ['source_ip', 'IP que chamou o coletor'], ['alg', 'Algoritmo do token'],
];
export function evidenceFacts(evidence) {
    return factLabels.filter(([key]) => evidence[key] !== undefined && evidence[key] !== null && evidence[key] !== '')
        .map(([key, label]) => [key, label, String(evidence[key])]);
}
export function crossAccount(evidence) {
    return evidence.cross_status !== undefined;
}
export function FindingCard({ finding, link = false }) {
    const [severity, tone] = severities[finding.severity] ?? [finding.severity, 'neutral'];
    const evidence = finding.evidence;
    const facts = evidenceFacts(evidence);
    return <article className="finding-item">
        <div className="finding-head">
            <span className={'finding-icon tone-' + tone}><Crosshair size={19} /></span>
            <div className="finding-title"><h3>{finding.title}</h3><p>{finding.category}{link && <> · <Link href={'/sessoes/' + finding.scan_id + '?aba=resultado'} className="mono finding-link">{scanLabel({ id: finding.scan_id })}</Link></>}</p></div>
            <Badge tone={tone}>{severity}</Badge>
        </div>
        <code className="evidence-route">{evidence.method} {evidence.path}</code>
        {evidence.kind ? <p className="evidence-detail">{evidence.detail}</p>
            : crossAccount(evidence) ? <dl className="evidence-grid"><div><dt>Sessão</dt><dd>{evidence.actor}</dd></div><div><dt>Proprietária</dt><dd>{evidence.owner}</dd></div><div><dt>Resposta</dt><dd>HTTP {evidence.cross_status}</dd></div></dl>
            : <>
                {evidence.detail && <p className="evidence-detail">{evidence.detail}</p>}
                {facts.length > 0 && <dl className="evidence-grid">{facts.map(([key, label, value]) => <div key={key}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>}
            </>}
        <details className="fix"><summary><ChevronRight size={15} />Como corrigir</summary><p>{finding.remediation}</p></details>
    </article>;
}
export function ScanResult({ scan }) {
    if (scan.status === 'completed' && outcomes[scan.result]) return <Badge tone={outcomes[scan.result][1]}>{outcomes[scan.result][0]}</Badge>;
    return <Status status={scan.status} />;
}
