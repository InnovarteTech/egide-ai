import { Link } from '@inertiajs/react';
import { Check, ChevronRight, Crosshair, Eye, Info, Sparkles, X } from 'lucide-react';
import { outcomes, severities, ruleLabel, scanLabel, plural } from './format';
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
    ['expected', 'Valor avaliado pelo alvo'],
];
export function evidenceFacts(evidence) {
    return factLabels.filter(([key]) => evidence[key] !== undefined && evidence[key] !== null && evidence[key] !== '')
        .map(([key, label]) => [key, label, String(evidence[key])]);
}
export function crossAccount(evidence) {
    return evidence.cross_status !== undefined;
}
export function cvssScore(finding) {
    const score = Number(finding.cvss_score);
    return finding.cvss_score === null || finding.cvss_score === undefined || Number.isNaN(score) ? null : score.toFixed(1);
}
export function Cvss({ finding, observation = false }) {
    const score = cvssScore(finding);
    if (score === null) return null;
    const severity = severities[finding.severity]?.[0] ?? finding.severity;
    return <div className="cvss-line">
        <span>{observation ? 'Se confirmada' : 'CVSS 3.1'}</span>
        <strong>{observation ? severity + ' · CVSS ' + score : score}</strong>
        {finding.cvss_vector && <code title="Vetor CVSS 3.1">{finding.cvss_vector}</code>}
    </div>;
}
export const observationNote = 'O oráculo registrou o indício, mas a prova não fechou: faltou reprodução ou o marcador não apareceu. Revise manualmente. Observações não contam como vulnerabilidade e ficam fora das contagens e do portão de CI.';
export function Observations({ observations = [], total, link = false }) {
    if (!observations.length) return null;
    const count = total ?? observations.length;
    return <section className="panel" aria-labelledby="observacoes-titulo">
        <div className="panel-header">
            <div><h2 id="observacoes-titulo">Observações para revisão</h2><p>{plural(count, 'indício', 'indícios')} sem prova completa{count > observations.length ? ' · ' + observations.length + ' mais recentes' : ''}</p></div>
            <Badge tone="amber">Não é vulnerabilidade</Badge>
        </div>
        <p className="observation-note"><Info size={16} /><span>{observationNote}</span></p>
        {observations.map(item => <FindingCard key={item.id} finding={item} link={link} observation />)}
    </section>;
}
export function FindingCard({ finding, link = false, observation = false }) {
    const [severity, tone] = severities[finding.severity] ?? [finding.severity, 'neutral'];
    const evidence = finding.evidence ?? {};
    const facts = evidenceFacts(evidence);
    const Icon = observation ? Eye : Crosshair;
    return <article className={'finding-item' + (observation ? ' is-observation' : '')}>
        <div className="finding-head">
            <span className={'finding-icon tone-' + (observation ? 'neutral' : tone)}><Icon size={19} /></span>
            <div className="finding-title"><h3>{finding.title}</h3><p>{finding.category}{link && <> · <Link href={'/sessoes/' + finding.scan_id + '?aba=resultado'} className="mono finding-link">{scanLabel({ id: finding.scan_id })}</Link></>}</p></div>
            {evidence.hunted && <span className="hunt-tag"><Sparkles size={13} />Caça agêntica</span>}
            <Badge tone={observation ? 'amber' : tone}>{observation ? 'Observação' : severity}</Badge>
        </div>
        <code className="evidence-route">{evidence.method} {evidence.path}</code>
        <Cvss finding={finding} observation={observation} />
        {evidence.kind ? <p className="evidence-detail">{evidence.detail}</p>
            : crossAccount(evidence) ? <dl className="evidence-grid"><div><dt>Sessão</dt><dd>{evidence.actor}</dd></div><div><dt>Proprietária</dt><dd>{evidence.owner}</dd></div><div><dt>Resposta</dt><dd>HTTP {evidence.cross_status}</dd></div></dl>
            : <>
                {evidence.detail && <p className="evidence-detail">{evidence.detail}</p>}
                {facts.length > 0 && <dl className="evidence-grid">{facts.map(([key, label, value]) => <div key={key}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>}
            </>}
        {evidence.rationale && <p className="evidence-rationale"><span>Raciocínio da IA</span>{evidence.rationale}</p>}
        {evidence.screenshot && <figure className="evidence-shot"><img src={'/achados/' + finding.id + '/imagem'} alt={observation ? 'Captura da tela no momento do indício' : 'Captura da tela no momento em que o oráculo provou a falha'} loading="lazy" /><figcaption>{observation ? 'Captura no instante do indício' : 'Captura no instante da prova'}</figcaption></figure>}
        <details className="fix"><summary><ChevronRight size={15} />{observation ? 'Como corrigir, se confirmar' : 'Como corrigir'}</summary><p>{finding.remediation}</p></details>
    </article>;
}
export function ScanResult({ scan }) {
    if (scan.status === 'completed' && outcomes[scan.result]) return <Badge tone={outcomes[scan.result][1]}>{outcomes[scan.result][0]}</Badge>;
    return <Status status={scan.status} />;
}
