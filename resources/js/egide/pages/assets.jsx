import { useRef, useState } from 'react';
import { Link, useForm, usePage } from '@inertiajs/react';
import { ArrowLeft, ArrowRight, Bird, Check, ChevronRight, Copy, Globe2, Info, Laptop, Layers3, LockKeyhole, Pencil, Plus, RefreshCw, ShieldAlert, ShieldCheck, Trash2, TriangleAlert, Upload } from 'lucide-react';
import { formatDate, plural } from '../format';
import { Badge, useTab, Tabs, TabPanel, Dialog, ConfirmAction, CopyBox, Empty, Field } from '../ui';
import { Layout, Heading } from '../layout';

const assetSections = {
    ambiente: ['name', 'origin', 'api_origin', 'entry_path', 'local_port', 'environment_type'],
    escopo: ['rules', 'denied'],
    seguranca: ['safety', 'approved_writes', 'max_rps', 'focus'],
    contas: ['record_hint', 'email_a', 'password_a', 'marker_a', 'origin_a', 'path_a', 'role_a', 'email_b', 'password_b', 'marker_b', 'origin_b', 'path_b', 'role_b'],
};
const steps = ['ambiente', 'escopo', 'seguranca', 'contas'];
const safetyModes = [
    ['canario', 'Canário', 'Escritas destrutivas (PUT, PATCH e DELETE fora da escrita de teste configurada) e ações de efeito externo são bloqueadas no proxy. Só passam a escrita de teste configurada e as escritas aprovadas.', Bird],
    ['livre', 'Livre', 'Escritas destrutivas autorizadas neste ambiente de teste. Ações de efeito externo continuam bloqueadas no proxy.', ShieldAlert],
];
const surfaceFormats = { openapi: 'OpenAPI 3', swagger: 'Swagger 2', postman: 'Postman', har: 'HAR' };
const newMarker = () => 'EGIDE-' + Array.from(crypto.getRandomValues(new Uint8Array(8)), byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
const blank = target => {
    if (!target) return { name: '', origin: '', api_origin: '', entry_path: '/', rules: 'GET /', denied: '', email_a: '', password_a: '', email_b: '', password_b: '', marker_a: newMarker(), marker_b: newMarker(), origin_a: '', origin_b: '', path_a: '', path_b: '', role_a: 'normal', role_b: 'normal', environment_type: 'production', record_hint: '', local_port: '', write_test: false, safety: 'canario', approved_writes: '', max_rps: '', focus: '' };
    const e = target.edit;
    return {
        name: e.name, origin: e.origin, api_origin: e.api_origin, entry_path: e.entry_path, rules: e.rules, denied: e.denied,
        safety: e.safety || 'canario', approved_writes: e.approved_writes ?? '', max_rps: e.max_rps ?? '', focus: e.focus ?? '',
        record_hint: e.record_hint, write_test: e.write_test, environment_type: e.environment_type || 'production', local_port: target.local_port ? String(target.local_port) : '',
        email_a: e.accounts.a.email, password_a: '', marker_a: e.accounts.a.marker || newMarker(), origin_a: e.accounts.a.origin, path_a: e.accounts.a.path, role_a: e.accounts.a.role || 'normal',
        email_b: e.accounts.b.email, password_b: '', marker_b: e.accounts.b.marker || newMarker(), origin_b: e.accounts.b.origin, path_b: e.accounts.b.path, role_b: e.accounts.b.role || 'normal',
    };
};
function AssetDialog({ open, onClose, localTargets, target }) {
    const editing = !!target;
    const [section, setSection] = useState('ambiente');
    const [actor, setActor] = useState('a');
    const [split, setSplit] = useState(editing ? !!target.edit.api_origin : false);
    const [copied, setCopied] = useState('');
    const form = useForm(blank(target));
    const step = steps.indexOf(section);
    const failing = key => assetSections[key].some(field => form.errors[field]);
    const actorFailing = value => ['email_', 'password_', 'marker_', 'origin_', 'path_', 'role_'].some(field => form.errors[field + value]);
    const submit = event => {
        event.preventDefault();
        if (step < steps.length - 1) { setSection(steps[step + 1]); return; }
        form.transform(data => ({ ...data, api_origin: split ? data.api_origin : '', marker_a: data.email_b ? data.marker_a : '', marker_b: data.email_b ? data.marker_b : '', write_test: data.email_b && data.path_a ? data.write_test : false, approved_writes: data.environment_type === 'test' ? data.approved_writes : '' }));
        const onError = errors => {
            const first = steps.find(key => assetSections[key].some(field => errors[field]));
            if (first) setSection(first);
            if (first === 'contas') setActor(['a', 'b'].find(value => Object.keys(errors).some(field => field.endsWith('_' + value))) ?? 'a');
        };
        if (editing) {
            form.put('/ambientes/' + target.id, { preserveScroll: true, preserveState: true, onSuccess: () => onClose(), onError });
        } else {
            form.post('/ambientes', {
                preserveScroll: true, preserveState: true,
                onSuccess: () => { form.setData(blank()); form.clearErrors(); setSplit(false); setSection('ambiente'); onClose(); },
                onError,
            });
        }
    };
    const input = (field, props = {}) => <input autoComplete="off" value={form.data[field]} onChange={e => form.setData(field, e.target.value)} {...props} />;
    const close = () => { form.reset('password_a', 'password_b'); onClose(); };
    const copy = value => { navigator.clipboard?.writeText(value).then(() => { setCopied(value); setTimeout(() => setCopied(''), 1600); }).catch(() => {}); };
    const markerField = 'marker_' + actor;
    const production = form.data.environment_type !== 'test';
    return <Dialog open={open} onClose={close} locked={form.processing} title={editing ? 'Editar ambiente' : 'Adicionar ambiente'} description="Quatro passos: o app, o que o agente pode acessar, a segurança do teste e as contas de teste." size="dialog-lg" footer={<>
        {step > 0
            ? <button type="button" className="button secondary" onClick={() => setSection(steps[step - 1])}><ArrowLeft size={16} /> Voltar</button>
            : <button type="button" className="button secondary" onClick={close}>Cancelar</button>}
        <button type="submit" form="asset-form" className="button primary" disabled={form.processing}>
            {step < steps.length - 1 ? <>Próximo <ArrowRight size={17} /></> : form.processing ? 'Salvando…' : <>{editing ? 'Salvar ambiente' : 'Cadastrar ambiente'} <Check size={17} /></>}
        </button>
    </>}>
        <Tabs name="ativo" label="Etapas do cadastro" value={section} onChange={setSection} className="dialog-tabs" tabs={[
            { key: 'ambiente', step: 1, label: 'App', alert: failing('ambiente') },
            { key: 'escopo', step: 2, label: 'Escopo', alert: failing('escopo') },
            { key: 'seguranca', step: 3, label: 'Segurança', alert: failing('seguranca') },
            { key: 'contas', step: 4, label: 'Contas de teste', alert: failing('contas') },
        ]} />
        <form id="asset-form" onSubmit={submit} noValidate>
            {section === 'ambiente' && <TabPanel name="ativo" id="ambiente" className="form-stack">
                <div className="fields-two">
                    <Field label="Nome do ambiente" error={form.errors.name}>{input('name', { placeholder: 'Portal de homologação', 'data-autofocus': true })}</Field>
                    <Field label="Endereço do app" error={form.errors.origin} help="O endereço que abre no navegador.">{input('origin', { type: 'url', placeholder: 'https://staging.empresa.com.br', inputMode: 'url' })}</Field>
                </div>
                <div className="fields-two">
                    <Field label="Caminho de entrada" error={form.errors.entry_path} help="Onde a sessão começa, como /login.">{input('entry_path', { className: 'mono-input' })}</Field>
                    {localTargets && <Field label="Porta local (opcional)" error={form.errors.local_port} help="Para origens em .local.egide.test, sem túnel.">{input('local_port', { type: 'number', min: 1, max: 65535, placeholder: '8080', inputMode: 'numeric' })}</Field>}
                </div>
                <div className="field">
                    <span className="field-title" id="api-place">Onde fica a API?</span>
                    <div className="segmented" role="group" aria-labelledby="api-place">
                        <button type="button" aria-pressed={!split} onClick={() => { setSplit(false); form.setData('api_origin', ''); }}>No mesmo domínio</button>
                        <button type="button" aria-pressed={split} onClick={() => setSplit(true)}>Em outro domínio</button>
                    </div>
                </div>
                {split && <Field label="Domínio da API" error={form.errors.api_origin} help="O proxy libera este domínio também. Ele precisa publicar o mesmo código de verificação.">{input('api_origin', { type: 'url', placeholder: 'https://api.empresa.com.br', inputMode: 'url' })}</Field>}
                <div className="field">
                    <span className="field-title" id="env-type">Tipo de ambiente</span>
                    <div className="segmented" role="group" aria-labelledby="env-type">
                        {[['test', 'Teste / homologação'], ['production', 'Produção']].map(([value, label]) => <button key={value} type="button" aria-pressed={form.data.environment_type === value} onClick={() => form.setData('environment_type', value)}>{label}</button>)}
                    </div>
                    <small>{form.data.environment_type === 'production'
                        ? 'Em produção a Égide só faz leitura: nada de escrita, injeção ou enumeração ativa.'
                        : 'Em teste a Égide roda a bateria completa (autorização, escrita reversível, injeção).'}</small>
                </div>
            </TabPanel>}
            {section === 'escopo' && <TabPanel name="ativo" id="escopo" className="form-stack">
                <div className="fields-two">
                    <Field label="Rotas permitidas" error={form.errors.rules} help={<>Uma por linha. Ex.: <code>GET /faturas/*</code>. <button type="button" className="text-link" onClick={() => form.setData('rules', '* /*')}>Liberar tudo</button></>}><textarea rows="7" className="mono-input" value={form.data.rules} onChange={e => form.setData('rules', e.target.value)} data-autofocus /></Field>
                    <Field label="Rotas bloqueadas" error={form.errors.denied} help="Uma por linha. Bloqueia o caminho e tudo abaixo."><textarea rows="7" className="mono-input" value={form.data.denied} onChange={e => form.setData('denied', e.target.value)} placeholder="/pagamentos" /></Field>
                </div>
                {form.data.rules.trim() === '* /*'
                    ? <p className="form-note form-note-warn"><TriangleAlert size={16} /><span>Tudo liberado{split ? ', no app e na API' : ''}, menos as rotas bloqueadas. Use só em ambiente de teste: o agente pode disparar escrita de verdade.</span></p>
                    : <p className="form-note"><LockKeyhole size={16} /><span>O proxy barra qualquer chamada fora dessas regras{split ? ', no app e na API' : ''}. Libere o POST do login, como <code>POST /auth/login</code>. <code>* /*</code> libera todos os métodos.</span></p>}
            </TabPanel>}
            {section === 'seguranca' && <TabPanel name="ativo" id="seguranca" className="form-stack">
                {production ? <p className="form-note"><LockKeyhole size={16} /><span>Produção roda só em mapeamento: PUT, PATCH, DELETE e ações de efeito externo são sempre bloqueados no proxy. Para testar escrita, marque o ambiente como teste na etapa App.</span></p>
                    : <>
                        <div className="field">
                            <span className="field-title" id="safety-mode">Segurança do teste</span>
                            <div className="mode-options two" role="radiogroup" aria-labelledby="safety-mode">{safetyModes.map(([value, label, detail, Icon]) => <label key={value} className={'mode-option ' + (form.data.safety === value ? 'selected' : '')}>
                                <input type="radio" name="safety" className="sr-only" checked={form.data.safety === value} onChange={() => form.setData('safety', value)} data-autofocus={form.data.safety === value || undefined} />
                                <span className="mode-icon"><Icon size={19} /></span>
                                <strong>{label}</strong>
                                <small>{detail}</small>
                                <span className="mode-check" aria-hidden="true"><Check size={13} /></span>
                            </label>)}</div>
                            {form.errors.safety && <small className="field-error" role="alert"><TriangleAlert size={13} />{form.errors.safety}</small>}
                        </div>
                        <Field label="Escritas aprovadas (opcional)" error={form.errors.approved_writes} help={<>Uma por linha, como <code>POST /convites</code> ou <code>DELETE /reservas/*</code>. Libera no proxy ações irreversíveis ou de efeito externo que você aprovou.</>}>
                            <textarea rows="4" className="mono-input" value={form.data.approved_writes} onChange={e => form.setData('approved_writes', e.target.value)} placeholder="POST /convites" />
                        </Field>
                    </>}
                <Field label="Limite de requisições por segundo (opcional)" error={form.errors.max_rps} help="De 0,1 a 50. Em branco, o proxy só desacelera quando o alvo responde 429.">{input('max_rps', { type: 'number', min: 0.1, max: 50, step: 0.1, inputMode: 'decimal', placeholder: '5', ...(production && { 'data-autofocus': true }) })}</Field>
                <Field label="Foco do teste (orientação para a IA)" error={form.errors.focus} help={form.data.focus.length + '/500. A IA prioriza o que você descrever, sem sair do escopo.'}>
                    <textarea rows="3" maxLength={500} value={form.data.focus} onChange={e => form.setData('focus', e.target.value)} placeholder="Priorize o módulo de faturas e a troca de plano." />
                </Field>
            </TabPanel>}
            {section === 'contas' && <TabPanel name="ativo" id="contas" className="form-stack">
                <p className="form-note"><Info size={16} /><span>A Égide entra com a conta B e tenta abrir um registro da conta A. Se o marcador de A aparecer, a falha está provada. Com uma conta só, ela apenas mapeia a navegação.</span></p>
                <Field label="Onde fica o registro de teste (opcional)" error={form.errors.record_hint} help="Dica para a IA: Clientes, Pedidos, Reservas.">{input('record_hint', { placeholder: 'Clientes' })}</Field>
                <div className="segmented" role="group" aria-label="Conta de teste">
                    {['a', 'b'].map(value => <button key={value} type="button" aria-pressed={actor === value} onClick={() => setActor(value)}>Conta {value.toUpperCase()}{actorFailing(value) && <i className="tab-alert" aria-label="Revise os campos" />}</button>)}
                </div>
                <div className="actor-fields" key={actor}>
                    <div className="fields-two">
                        <Field label="Login" error={form.errors['email_' + actor]}>{input('email_' + actor)}</Field>
                        <Field label="Senha" error={form.errors['password_' + actor]}><input type="password" autoComplete="new-password" placeholder={editing ? 'manter atual' : ''} value={form.data['password_' + actor]} onChange={e => form.setData('password_' + actor, e.target.value)} /></Field>
                    </div>
                    <Field label="Papel desta conta" error={form.errors['role_' + actor]} help="Admin alcança rotas privilegiadas; Comum é usuário sem privilégio. A Égide usa os dois para provar falha de autorização por função.">
                        <div className="segmented" role="group" aria-label={'Papel da conta ' + actor.toUpperCase()}>
                            {[['normal', 'Comum'], ['admin', 'Admin']].map(([value, label]) => <button key={value} type="button" aria-pressed={form.data['role_' + actor] === value} onClick={() => form.setData('role_' + actor, value)}>{label}</button>)}
                        </div>
                    </Field>
                    <div className="marker-row">
                        <Field label="Marcador do registro" error={form.errors[markerField]} help="Use este texto como nome de um registro só desta conta.">{input(markerField, { className: 'mono-input', placeholder: 'EGIDE-0123456789ABCDEF' })}</Field>
                        <div className="marker-actions">
                            <button type="button" className="button secondary compact" onClick={() => copy(form.data[markerField])}>{copied && copied === form.data[markerField] ? <><Check size={14} /> Copiado</> : <><Copy size={14} /> Copiar</>}</button>
                            <button type="button" className="button secondary compact" onClick={() => form.setData(markerField, newMarker())}><RefreshCw size={14} /> Gerar outro</button>
                        </div>
                    </div>
                    <div className="fields-two">
                        <Field label="Subdomínio da conta (opcional)" error={form.errors['origin_' + actor]} help="Para SaaS com um subdomínio por empresa.">{input('origin_' + actor, { type: 'url', placeholder: 'https://empresa-' + actor + '.seuapp.com.br' })}</Field>
                        <Field label="Rota do registro (opcional)" error={form.errors['path_' + actor]} help={split ? 'Rota na API, como /reservas/12.' : 'Se a tela não carrega o registro sozinha.'}>{input('path_' + actor, { placeholder: split ? '/reservas/12' : '/api/pedidos/123', className: 'mono-input' })}</Field>
                    </div>
                </div>
                {form.data.email_b && form.data.path_a && <label className="switch-row">
                    <input type="checkbox" role="switch" checked={form.data.write_test} onChange={e => form.setData('write_test', e.target.checked)} />
                    <span className="switch" aria-hidden="true" />
                    <span><strong>Testar escrita entre contas</strong><small>A conta B tenta alterar o registro da conta A. A Égide usa só esse registro, método reversível (PATCH) e restaura o valor no fim.</small></span>
                </label>}
                {form.errors.write_test && <p role="alert" className="field-error"><TriangleAlert size={13} />{form.errors.write_test}</p>}
            </TabPanel>}
        </form>
    </Dialog>;
}
export function Assets({ targets, localTargets }) {
    const [adding, setAdding] = useState(false);
    const [editing, setEditing] = useState(null);
    const [tab, setTab] = useTab('aba', 'ambientes', ['ambientes', 'local']);
    const { errors } = usePage().props;
    const pending = targets.filter(target => !target.verified_at).length;
    return <Layout title="Ambientes">
        <Heading title="Ambientes" description="Sistemas autorizados e regras de teste.">
            <button type="button" className="button primary" onClick={() => setAdding(true)}><Plus size={19} /> Adicionar ambiente</button>
        </Heading>
        {errors.verification && <div className="notice error-notice" role="alert"><TriangleAlert size={16} />{errors.verification}</div>}
        <Tabs name="ativos" label="Seções" value={tab} onChange={setTab} className="page-tabs" tabs={[
            { key: 'ambientes', label: 'Cadastrados', icon: Layers3, count: targets.length },
            { key: 'local', label: 'App na sua máquina', icon: Laptop },
        ]} />
        {tab === 'ambientes' && <TabPanel name="ativos" id="ambientes">
            <section className="panel">
                <div className="panel-header"><div><h2>Ambientes cadastrados</h2><p>{pending ? plural(pending, 'aguardando verificação', 'aguardando verificação') : 'Todos verificados'}</p></div></div>
                {!targets.length && <Empty icon={Layers3} title="Nenhum ambiente cadastrado" action={<button type="button" className="text-link" onClick={() => setAdding(true)}>Adicionar primeiro ambiente <ArrowRight size={16} /></button>}>Adicione e verifique um ambiente para iniciar uma exploração externa.</Empty>}
                <ul className="asset-list">{targets.map(target => <AssetRow key={target.id} target={target} onEdit={() => setEditing(target)} />)}</ul>
            </section>
        </TabPanel>}
        {tab === 'local' && <TabPanel name="ativos" id="local">
            <section className="panel">
                <div className="panel-header"><div><h2>Testar um app da sua máquina</h2><p>Use dados de teste. Nada do seu código é enviado.</p></div></div>
                <div className="guide">
                    {localTargets && <div className="guide-item">
                        <div className="guide-title"><h3>Sem túnel</h3><Badge tone="green">Recomendado</Badge></div>
                        <p>Cadastre o ambiente com a porta local e uma origem terminada em <code>.local.egide.test</code>. O executor acessa a porta da sua máquina e nada fica exposto na internet.</p>
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
        {editing && <AssetDialog key={editing.id} open target={editing} onClose={() => setEditing(null)} localTargets={localTargets} />}
    </Layout>;
}
export function Preflight({ items = [], title = 'Pré-voo' }) {
    const ready = items.filter(item => item.ok).length;
    return <div className="preflight">
        <div className="preflight-head"><strong>{title}</strong><Badge tone={ready === items.length ? 'green' : 'amber'}>{ready} de {items.length} prontos</Badge></div>
        <ul className="preflight-list">{items.map(item => <li key={item.label} className={item.ok ? 'is-ok' : 'is-pending'}>
            <span className="preflight-icon" aria-hidden="true">{item.ok ? <Check size={13} /> : <TriangleAlert size={12} />}</span>
            <span><strong>{item.label}<span className="sr-only">{item.ok ? ': pronto' : ': pendente'}</span></strong><small>{item.detail}</small></span>
        </li>)}</ul>
    </div>;
}
function Surface({ target }) {
    const meta = target.surface_meta;
    const [via, setVia] = useState('arquivo');
    const file = useRef(null);
    const form = useForm({ arquivo: null, url: '' });
    const submit = event => {
        event.preventDefault();
        form.transform(data => (via === 'arquivo' ? { arquivo: data.arquivo } : { url: data.url }));
        form.post('/ambientes/' + target.id + '/superficie', {
            forceFormData: true, preserveScroll: true, preserveState: true,
            onSuccess: () => { form.reset(); if (file.current) file.current.value = ''; },
        });
    };
    const switchTo = value => { setVia(value); form.clearErrors(); };
    return <div className="surface-box">
        <div className="preflight-head"><strong>Superfície da API</strong>{meta?.count ? <Badge tone="green">{plural(meta.count, 'rota', 'rotas')}</Badge> : <Badge>Opcional</Badge>}</div>
        {meta?.count ? <div className="surface-meta">
            <span>{surfaceFormats[meta.format] ?? meta.format} · {meta.via === 'url' ? 'por URL' : 'por arquivo'}{meta.imported_at && ' · ' + formatDate(meta.imported_at)}</span>
            {meta.name && <code>{meta.name}</code>}
            {meta.skipped_hosts?.length > 0 && <small>Endereços fora do ambiente ignorados: {meta.skipped_hosts.slice(0, 3).join(', ')}</small>}
            <ConfirmAction href={'/ambientes/' + target.id + '/superficie'} method="delete" title="Remover a superfície importada?" description="As rotas importadas deixam de entrar nas próximas sessões. As sessões já feitas continuam no histórico." confirmLabel="Remover superfície" className="text-link surface-remove"><Trash2 size={14} /> Remover</ConfirmAction>
        </div> : <p>Envie OpenAPI, Swagger, Postman ou HAR para a Égide testar rotas que a navegação não alcança. Só entram rotas das origens deste ambiente.</p>}
        <form className="surface-form" onSubmit={submit} noValidate>
            <div className="segmented" role="group" aria-label={'Origem do documento de ' + target.name}>
                <button type="button" aria-pressed={via === 'arquivo'} onClick={() => switchTo('arquivo')}>Arquivo</button>
                <button type="button" aria-pressed={via === 'url'} onClick={() => switchTo('url')}>URL</button>
            </div>
            {via === 'arquivo'
                ? <Field label="Arquivo" error={form.errors.arquivo} help="JSON, YAML ou HAR, até 5 MB."><input ref={file} type="file" accept=".json,.yaml,.yml,.har,application/json" onChange={e => form.setData('arquivo', e.target.files?.[0] ?? null)} /></Field>
                : <Field label="URL do documento" error={form.errors.url} help={target.verified_at ? 'HTTPS de uma das origens do ambiente, sem redirecionamento.' : 'Verifique o domínio antes de importar por URL, ou envie o arquivo.'}><input type="url" inputMode="url" autoComplete="off" value={form.data.url} onChange={e => form.setData('url', e.target.value)} placeholder={(target.api_origin || target.origin) + '/openapi.json'} /></Field>}
            <button type="submit" className="button secondary compact" disabled={form.processing || (via === 'arquivo' ? !form.data.arquivo : !form.data.url)}><Upload size={15} /> {form.processing ? 'Importando…' : meta?.count ? 'Substituir superfície' : 'Importar superfície'}</button>
        </form>
    </div>;
}
const safetyBadge = target => target.environment_type !== 'test' ? ['Só mapeamento', 'neutral'] : target.safety === 'livre' ? ['Livre', 'amber'] : ['Canário', 'violet'];
function AssetRow({ target, onEdit }) {
    const schedule = target.schedule ?? 'off';
    const [safety, safetyTone] = safetyBadge(target);
    const ready = (target.preflight ?? []).filter(item => item.ok).length;
    return <li className="asset-row">
        <div className="asset-head">
            <span className={'asset-icon ' + (target.verified_at ? 'is-verified' : '')}>{target.verified_at ? <ShieldCheck size={19} /> : <Globe2 size={19} />}</span>
            <div className="asset-main"><h3>{target.name}</h3><p className="mono">{target.origin}{target.api_origin && <span className="asset-api"> · API {target.api_origin.replace('https://', '')}</span>}</p></div>
            <div className="asset-tags">
                {target.local_port && <Badge tone="violet">{'Local · ' + target.local_port}</Badge>}
                {target.write_test && <Badge tone="amber">Escrita</Badge>}
                <Badge tone={safetyTone}>{safety}</Badge>
                <Badge tone={target.verified_at ? 'green' : 'neutral'}>{target.verified_at ? 'Verificado' : 'Pendente'}</Badge>
            </div>
            <div className="asset-actions">
                <button type="button" className="icon-button" title="Editar ambiente" aria-label="Editar ambiente" onClick={onEdit}><Pencil size={16} /></button>
                <ConfirmAction href={'/ambientes/' + target.id} method="delete" title={'Remover ' + target.name + '?'} description="O ambiente e as regras saem do workspace. As sessões já feitas continuam no histórico." confirmLabel="Remover ambiente" className="icon-button"><Trash2 size={16} /></ConfirmAction>
            </div>
        </div>
        {target.verified_at ? <div className="asset-foot">
            <span className="asset-label">Reteste automático</span>
            <div className="segmented" role="group" aria-label={'Reteste automático de ' + target.name}>
                {[['off', 'Desligado'], ['daily', 'Diário'], ['weekly', 'Semanal']].map(([value, label]) => <Link key={value} href={'/ambientes/' + target.id + '/agenda'} method="put" data={{ schedule: value }} as="button" preserveScroll aria-pressed={schedule === value}>{label}</Link>)}
            </div>
            {target.next_run_at && <span className="asset-next"><RefreshCw size={13} /> {formatDate(target.next_run_at)}</span>}
        </div> : <div className="asset-verify">
            <div className="verify-head"><strong>Verificar por DNS</strong><Badge tone="violet">Recomendado</Badge></div>
            <p>Adicione {target.verify_dns?.length > 1 ? 'os registros TXT abaixo' : 'este registro TXT'} no DNS do seu domínio. Prova o domínio inteiro de uma vez, cobrindo front, API e contas.</p>
            {(target.verify_dns ?? []).map(record => <div key={record.domain} className="dns-record">
                <div className="dns-field"><span className="dns-key">Tipo</span><span className="mono dns-val">TXT</span></div>
                <div className="dns-field"><span className="dns-key">Nome</span><span className="mono dns-val">{record.host}</span><small>no domínio {record.domain}</small></div>
                <div className="dns-field dns-value"><span className="dns-key">Valor</span><CopyBox value={record.value} /></div>
            </div>)}
            <details className="disclosure verify-file">
                <summary><ChevronRight size={15} />ou verificar por arquivo</summary>
                <div className="disclosure-body">
                    <p>Publique este código em <code>/.well-known/egide-verification.txt</code>{target.verify_urls?.length > 1 ? ' em cada endereço:' : ':'}</p>
                    {target.verify_urls?.length > 1 && <ul className="verify-urls">{target.verify_urls.map(url => <li key={url} className="mono">{url}</li>)}</ul>}
                    <CopyBox value={target.verification_token} />
                </div>
            </details>
            <div className="asset-verify-actions">
                <Link href={'/ambientes/' + target.id + '/verificar'} method="post" as="button" className="button primary compact"><ShieldCheck size={16} /> Verificar domínio</Link>
            </div>
        </div>}
        <details className="asset-prep">
            <summary><ChevronRight size={15} />Pré-voo e superfície<Badge tone={ready === target.preflight?.length ? 'green' : 'amber'}>{ready} de {target.preflight?.length ?? 0}</Badge>{target.surface_meta?.count > 0 && <Badge tone="violet">{plural(target.surface_meta.count, 'rota importada', 'rotas importadas')}</Badge>}</summary>
            <div className="asset-prep-body">
                <Preflight items={target.preflight} />
                <Surface target={target} />
            </div>
        </details>
    </li>;
}
