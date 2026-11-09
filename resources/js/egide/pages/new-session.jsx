import { Link, useForm, usePage } from '@inertiajs/react';
import { ArrowRight, Check, CirclePlay, Globe2, Info, Monitor, RefreshCw, ShieldCheck, TriangleAlert } from 'lucide-react';
import { scanLabel } from '../format';
import { Field } from '../ui';
import { Layout, Heading } from '../layout';

export function NewSession({ targets, initial, externalEngine, labEngine, initialAgent, previous }) {
    const { auth } = usePage().props;
    const mode = ['laboratory', 'retest', 'external'].includes(initial) ? initial : 'laboratory';
    const form = useForm({ mode: previous ? 'external' : mode, target_id: previous?.target_id ?? targets[0]?.id ?? '', budget: previous?.budget ?? 80, authorized: false, agent: initialAgent, retest_of: previous?.id ?? null });
    const target = targets.find(item => String(item.id) === String(form.data.target_id));
    const external = form.data.mode === 'external';
    const blocked = external && (!target || !externalEngine);
    const modes = [
        ['laboratory', 'Laboratório', 'App vulnerável com dados fictícios.', CirclePlay],
        ['retest', 'Reteste', 'Versão corrigida, mesma prova.', RefreshCw],
        ['external', 'Ambiente verificado', 'Seu domínio, no escopo cadastrado.', Globe2],
    ];
    return <Layout title="Nova sessão">
        <Heading title="Nova sessão" description="Escolha o ambiente e os limites da avaliação." />
        <form className="form-layout" onSubmit={e => { e.preventDefault(); form.post('/sessoes'); }}>
            <section className="panel">
                {form.errors.mode && <div className="notice error-notice inset" role="alert"><TriangleAlert size={16} />{form.errors.mode}</div>}
                <fieldset className="form-section">
                    <legend>Ambiente</legend>
                    {previous ? <p className="form-note"><RefreshCw size={16} /><span>Reteste do achado da sessão <strong>{scanLabel(previous)}</strong> em {previous.name}.</span></p>
                        : <div className="mode-options">{modes.map(([value, label, detail, Icon]) => <label className={'mode-option ' + (form.data.mode === value ? 'selected' : '')} key={value}>
                            <input type="radio" name="mode" className="sr-only" checked={form.data.mode === value} onChange={() => form.setData('mode', value)} />
                            <span className="mode-icon"><Icon size={19} /></span>
                            <strong>{label}</strong>
                            <small>{detail}</small>
                            <span className="mode-check" aria-hidden="true"><Check size={13} /></span>
                        </label>)}</div>}
                    {external && <div className="form-stack">
                        <Field label="Ambiente" error={form.errors.target_id}><select value={form.data.target_id} required disabled={!!previous} onChange={e => form.setData('target_id', e.target.value)}><option value="">Selecione um ambiente verificado</option>{targets.map(item => <option value={item.id} key={item.id}>{item.name} · {item.origin}</option>)}</select></Field>
                        {blocked && <div className="callout"><Info size={16} /><div><strong>Falta preparar o ambiente</strong><div className="callout-links">{!target && <Link href="/ambientes" className="text-link">Verificar um ambiente <ArrowRight size={14} /></Link>}{!externalEngine && (auth?.is_admin ? <Link href="/admin?aba=motor" className="text-link">Configurar o motor de IA <ArrowRight size={14} /></Link> : <span>O motor de IA ainda não foi ativado pelo administrador.</span>)}</div></div></div>}
                        {target && externalEngine && <p className="form-note"><ShieldCheck size={16} /><span>{target.comparison ? 'Prova de acesso entre duas contas' : 'Mapeamento da navegação'} · {externalEngine}</span></p>}
                        <label className="consent"><input type="checkbox" required checked={form.data.authorized} onChange={e => form.setData('authorized', e.target.checked)} /><span><strong>Confirmo a autorização</strong><small>Tenho permissão para testar este ambiente dentro do escopo cadastrado.</small></span></label>
                    </div>}
                </fieldset>
                <fieldset className="form-section">
                    <legend>Limites</legend>
                    <div className={'field range-field ' + (form.errors.budget ? 'has-error' : '')}>
                        <div className="range-head"><label htmlFor="budget">Limite de requisições</label><output htmlFor="budget">{form.data.budget}</output></div>
                        <input id="budget" type="range" min="10" max="180" step="5" value={form.data.budget} onChange={e => form.setData('budget', Number(e.target.value))} style={{ '--fill': ((form.data.budget - 10) / 170) * 100 + '%' }} />
                        <div className="range-scale"><span>10</span><span>180</span></div>
                        {form.errors.budget && <small className="field-error" role="alert"><TriangleAlert size={13} />{form.errors.budget}</small>}
                    </div>
                    {!external && (labEngine || form.data.agent) && <label className="switch-row">
                        <input type="checkbox" role="switch" checked={form.data.agent} onChange={e => form.setData('agent', e.target.checked)} />
                        <span className="switch" aria-hidden="true" />
                        <span><strong>Explorar com IA</strong><small>{labEngine ? 'Motor: ' + labEngine : 'Nenhum motor configurado'}</small></span>
                    </label>}
                    {form.errors.agent && <p role="alert" className="field-error"><TriangleAlert size={13} />{form.errors.agent}</p>}
                </fieldset>
                <div className="panel-foot">
                    <Link href="/sessoes" className="button secondary">Voltar</Link>
                    <button className="button primary" disabled={form.processing || blocked}><CirclePlay size={18} /> {form.processing ? 'Enviando…' : previous ? 'Iniciar reteste' : 'Iniciar sessão'}</button>
                </div>
            </section>
            <aside className="panel side-card">
                <h2>Durante a sessão</h2>
                <ul className="side-list">
                    <li><span className="side-icon"><Monitor size={17} /></span><span><strong>Firefox ao vivo</strong><small>Uma captura a cada passo do agente.</small></span></li>
                    <li><span className="side-icon"><Globe2 size={17} /></span><span><strong>Chamadas de rede</strong><small>Cada requisição com o status recebido.</small></span></li>
                    <li><span className="side-icon"><ShieldCheck size={17} /></span><span><strong>Escopo no proxy</strong><small>Fora das regras, a chamada é barrada.</small></span></li>
                </ul>
            </aside>
        </form>
    </Layout>;
}
