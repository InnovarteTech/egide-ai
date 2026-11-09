import { useState } from 'react';
import { Link, useForm, usePage } from '@inertiajs/react';
import { ArrowRight, Globe2, Info, Laptop, Layers3, LockKeyhole, Plus, RefreshCw, ShieldCheck, TriangleAlert } from 'lucide-react';
import { formatDate, plural } from '../format';
import { Badge, useTab, Tabs, TabPanel, Dialog, CopyBox, Empty, Field } from '../ui';
import { Layout, Heading } from '../layout';

const assetSections = {
    ambiente: ['name', 'origin', 'entry_path', 'local_port'],
    escopo: ['rules', 'denied'],
    contas: ['record_hint', 'email_a', 'password_a', 'marker_a', 'origin_a', 'path_a', 'email_b', 'password_b', 'marker_b', 'origin_b', 'path_b'],
};
function AssetDialog({ open, onClose, localTargets }) {
    const [section, setSection] = useState('ambiente');
    const [actor, setActor] = useState('a');
    const form = useForm({ name: '', origin: '', entry_path: '/', rules: 'GET /', denied: '', email_a: '', password_a: '', email_b: '', password_b: '', marker_a: '', marker_b: '', origin_a: '', origin_b: '', path_a: '', path_b: '', record_hint: '', local_port: '' });
    const failing = key => assetSections[key].some(field => form.errors[field]);
    const actorFailing = value => ['email_', 'password_', 'marker_', 'origin_', 'path_'].some(field => form.errors[field + value]);
    const submit = event => {
        event.preventDefault();
        form.post('/ativos', {
            preserveScroll: true, preserveState: true,
            onSuccess: () => { form.reset(); setSection('ambiente'); onClose(); },
            onError: errors => {
                const first = Object.keys(assetSections).find(key => assetSections[key].some(field => errors[field]));
                if (first) setSection(first);
                if (first === 'contas') setActor(['a', 'b'].find(value => Object.keys(errors).some(field => field.endsWith('_' + value))) ?? 'a');
            },
        });
    };
    const input = (field, props = {}) => <input autoComplete="off" value={form.data[field]} onChange={e => form.setData(field, e.target.value)} {...props} />;
    const close = () => { form.reset('password_a', 'password_b'); onClose(); };
    return <Dialog open={open} onClose={close} locked={form.processing} title="Adicionar ativo" description="Cadastre o ambiente e o que o agente pode acessar." size="dialog-lg" footer={<>
        <button type="button" className="button secondary" onClick={close}>Cancelar</button>
        <button type="submit" form="asset-form" className="button primary" disabled={form.processing}>{form.processing ? 'Cadastrando…' : 'Cadastrar ativo'} <ArrowRight size={17} /></button>
    </>}>
        <Tabs name="ativo" label="Etapas do cadastro" value={section} onChange={setSection} className="dialog-tabs" tabs={[
            { key: 'ambiente', label: 'Ambiente', alert: failing('ambiente') },
            { key: 'escopo', label: 'Escopo', alert: failing('escopo') },
            { key: 'contas', label: 'Contas de teste', alert: failing('contas') },
        ]} />
        <form id="asset-form" onSubmit={submit} noValidate>
            {section === 'ambiente' && <TabPanel name="ativo" id="ambiente" className="form-stack">
                <div className="fields-two">
                    <Field label="Nome do ativo" error={form.errors.name}>{input('name', { placeholder: 'Portal de homologação', 'data-autofocus': true })}</Field>
                    <Field label="Origem HTTPS" error={form.errors.origin} help="Domínio do ambiente de teste.">{input('origin', { type: 'url', placeholder: 'https://staging.empresa.com.br', inputMode: 'url' })}</Field>
                </div>
                <div className="fields-two">
                    <Field label="Caminho de entrada" error={form.errors.entry_path}>{input('entry_path', { className: 'mono-input' })}</Field>
                    {localTargets && <Field label="Porta local (opcional)" error={form.errors.local_port} help="Para origens em .local.egide.test, sem túnel.">{input('local_port', { type: 'number', min: 1, max: 65535, placeholder: '8080', inputMode: 'numeric' })}</Field>}
                </div>
            </TabPanel>}
            {section === 'escopo' && <TabPanel name="ativo" id="escopo" className="form-stack">
                <div className="fields-two">
                    <Field label="Rotas permitidas" error={form.errors.rules} help="Uma por linha. Ex.: GET /faturas/*"><textarea rows="6" className="mono-input" value={form.data.rules} onChange={e => form.setData('rules', e.target.value)} data-autofocus /></Field>
                    <Field label="Rotas bloqueadas" error={form.errors.denied} help="Uma por linha. Bloqueia o caminho e tudo abaixo."><textarea rows="6" className="mono-input" value={form.data.denied} onChange={e => form.setData('denied', e.target.value)} placeholder="/pagamentos" /></Field>
                </div>
                <p className="form-note"><LockKeyhole size={16} /><span>O proxy barra qualquer chamada fora dessas regras.</span></p>
            </TabPanel>}
            {section === 'contas' && <TabPanel name="ativo" id="contas" className="form-stack">
                <p className="form-note"><Info size={16} /><span>Duas contas com um registro marcado provam o isolamento. Com uma conta, a sessão só mapeia a navegação.</span></p>
                <Field label="Onde fica o registro de teste (opcional)" error={form.errors.record_hint} help="Dica para a IA: Clientes, Pedidos, Faturas.">{input('record_hint', { placeholder: 'Clientes' })}</Field>
                <div className="segmented" role="group" aria-label="Conta de teste">
                    {['a', 'b'].map(value => <button key={value} type="button" aria-pressed={actor === value} onClick={() => setActor(value)}>Conta {value.toUpperCase()}{actorFailing(value) && <i className="tab-alert" aria-label="Revise os campos" />}</button>)}
                </div>
                <div className="actor-fields" key={actor}>
                    <div className="fields-two">
                        <Field label="Login" error={form.errors['email_' + actor]}>{input('email_' + actor)}</Field>
                        <Field label="Senha" error={form.errors['password_' + actor]}><input type="password" autoComplete="new-password" value={form.data['password_' + actor]} onChange={e => form.setData('password_' + actor, e.target.value)} /></Field>
                    </div>
                    <Field label="Marcador do registro" error={form.errors['marker_' + actor]} help="EGIDE- seguido de 16 caracteres hexadecimais maiúsculos.">{input('marker_' + actor, { placeholder: 'EGIDE-0123456789ABCDEF', className: 'mono-input' })}</Field>
                    <div className="fields-two">
                        <Field label="Subdomínio da conta (opcional)" error={form.errors['origin_' + actor]} help="Para SaaS com um subdomínio por empresa.">{input('origin_' + actor, { type: 'url', placeholder: 'https://empresa-' + actor + '.seuapp.com.br' })}</Field>
                        <Field label="Rota do registro (opcional)" error={form.errors['path_' + actor]} help="Se a tela não carrega o registro sozinha.">{input('path_' + actor, { placeholder: '/api/pedidos/123', className: 'mono-input' })}</Field>
                    </div>
                </div>
            </TabPanel>}
        </form>
    </Dialog>;
}
export function Assets({ targets, localTargets }) {
    const [adding, setAdding] = useState(false);
    const [tab, setTab] = useTab('aba', 'ambientes', ['ambientes', 'local']);
    const { errors } = usePage().props;
    const pending = targets.filter(target => !target.verified_at).length;
    return <Layout title="Ativos">
        <Heading title="Ativos" description="Ambientes autorizados e regras de teste.">
            <button type="button" className="button primary" onClick={() => setAdding(true)}><Plus size={19} /> Adicionar ativo</button>
        </Heading>
        {errors.verification && <div className="notice error-notice" role="alert"><TriangleAlert size={16} />{errors.verification}</div>}
        <Tabs name="ativos" label="Seções" value={tab} onChange={setTab} className="page-tabs" tabs={[
            { key: 'ambientes', label: 'Ambientes', icon: Layers3, count: targets.length },
            { key: 'local', label: 'App na sua máquina', icon: Laptop },
        ]} />
        {tab === 'ambientes' && <TabPanel name="ativos" id="ambientes">
            <section className="panel">
                <div className="panel-header"><div><h2>Ambientes cadastrados</h2><p>{pending ? plural(pending, 'aguardando verificação', 'aguardando verificação') : 'Todos verificados'}</p></div></div>
                {!targets.length && <Empty icon={Layers3} title="Nenhum ativo cadastrado" action={<button type="button" className="text-link" onClick={() => setAdding(true)}>Adicionar primeiro ativo <ArrowRight size={16} /></button>}>Adicione e verifique um ambiente para iniciar uma exploração externa.</Empty>}
                <ul className="asset-list">{targets.map(target => <AssetRow key={target.id} target={target} />)}</ul>
            </section>
        </TabPanel>}
        {tab === 'local' && <TabPanel name="ativos" id="local">
            <section className="panel">
                <div className="panel-header"><div><h2>Testar um app da sua máquina</h2><p>Use dados de teste. Nada do seu código é enviado.</p></div></div>
                <div className="guide">
                    {localTargets && <div className="guide-item">
                        <div className="guide-title"><h3>Sem túnel</h3><Badge tone="green">Recomendado</Badge></div>
                        <p>Cadastre o ativo com a porta local e uma origem terminada em <code>.local.egide.test</code>. O executor acessa a porta da sua máquina e nada fica exposto na internet.</p>
                        <p className="muted small">Subdomínio por empresa: <code>https://empresa-a.local.egide.test</code></p>
                    </div>}
                    <div className="guide-item">
                        <div className="guide-title"><h3>Com túnel</h3></div>
                        <p>Publica o app em um HTTPS temporário, serve o código de verificação e repassa o resto. Encerre com Ctrl+C.</p>
                        <pre className="code-block">{'bin/egide-local --porta 8080\n\n# API em outra porta\nbin/egide-local --porta 8080 --rota /api=3001'}</pre>
                    </div>
                </div>
            </section>
        </TabPanel>}
        <AssetDialog open={adding} onClose={() => setAdding(false)} localTargets={localTargets} />
    </Layout>;
}
function AssetRow({ target }) {
    const schedule = target.schedule ?? 'off';
    return <li className="asset-row">
        <div className="asset-head">
            <span className={'asset-icon ' + (target.verified_at ? 'is-verified' : '')}>{target.verified_at ? <ShieldCheck size={19} /> : <Globe2 size={19} />}</span>
            <div className="asset-main"><h3>{target.name}</h3><p className="mono">{target.origin}</p></div>
            <div className="asset-tags">
                {target.local_port && <Badge tone="violet">{'Local · ' + target.local_port}</Badge>}
                <Badge tone={target.verified_at ? 'green' : 'neutral'}>{target.verified_at ? 'Verificado' : 'Pendente'}</Badge>
            </div>
        </div>
        {target.verified_at ? <div className="asset-foot">
            <span className="asset-label">Reteste automático</span>
            <div className="segmented" role="group" aria-label={'Reteste automático de ' + target.name}>
                {[['off', 'Desligado'], ['daily', 'Diário'], ['weekly', 'Semanal']].map(([value, label]) => <Link key={value} href={'/ativos/' + target.id + '/agenda'} method="put" data={{ schedule: value }} as="button" preserveScroll aria-pressed={schedule === value}>{label}</Link>)}
            </div>
            {target.next_run_at && <span className="asset-next"><RefreshCw size={13} /> {formatDate(target.next_run_at)}</span>}
        </div> : <div className="asset-verify">
            <p>Publique este código em <code>/.well-known/egide-verification.txt</code> e confirme.</p>
            <div className="asset-verify-actions">
                <CopyBox value={target.verification_token} />
                <Link href={'/ativos/' + target.id + '/verificar'} method="post" as="button" className="button primary compact"><ShieldCheck size={16} /> Verificar domínio</Link>
            </div>
        </div>}
    </li>;
}
