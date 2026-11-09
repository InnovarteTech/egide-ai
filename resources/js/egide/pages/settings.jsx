import { useEffect, useState } from 'react';
import { useForm } from '@inertiajs/react';
import { ArrowDownToLine, Check, ChevronRight, KeyRound, LayoutGrid, Plus, ScanLine, TriangleAlert, X } from 'lucide-react';
import { formatDate } from '../format';
import { Badge, useTab, Tabs, TabPanel, Dialog, ConfirmAction, CopyBox, Empty, Field } from '../ui';
import { Layout, Heading } from '../layout';

function Integrations({ hasWebhook, tokens, issuedToken, apiBase }) {
    const [creating, setCreating] = useState(false);
    const [revealed, setRevealed] = useState(!!issuedToken);
    useEffect(() => { if (issuedToken) setRevealed(true); }, [issuedToken]);
    const tokenForm = useForm({ name: '' });
    const hookForm = useForm({ webhook_url: '' });
    const ci = `EGIDE_API=${apiBase}\nRESPOSTA=$(curl -s -X POST "$EGIDE_API/sessoes" -H "Authorization: Bearer $EGIDE_TOKEN" -H "Content-Type: application/json" -d '{"ativo": 1}')\nID=$(echo "$RESPOSTA" | jq -r .id)\ncurl -s "$EGIDE_API/sessoes/$ID" -H "Authorization: Bearer $EGIDE_TOKEN"`;
    return <div className="stack">
        <section className="panel">
            <div className="panel-header"><div><h2>Tokens de API</h2><p>Dispare uma sessão a cada deploy e falhe o pipeline em achado grave.</p></div><button type="button" className="button primary compact" onClick={() => setCreating(true)}><Plus size={16} /> Gerar token</button></div>
            {tokens.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Nome</th><th>Prefixo</th><th className="hide-sm">Último uso</th><th><span className="sr-only">Ação</span></th></tr></thead><tbody>
                {tokens.map(token => <tr key={token.id}><td><strong>{token.name}</strong></td><td className="mono">{token.prefix}…</td><td className="mono hide-sm muted">{formatDate(token.last_used_at)}</td>
                    <td className="cell-action"><ConfirmAction href={'/configuracoes/tokens/' + token.id} method="delete" title="Revogar token?" description={'Integrações que usam "' + token.name + '" param de funcionar na hora.'} confirmLabel="Revogar token"><X size={14} /> Revogar</ConfirmAction></td></tr>)}
            </tbody></table></div> : <Empty icon={KeyRound} title="Nenhum token criado">Gere um token para usar a API ou o GitHub Actions.</Empty>}
            <details className="disclosure">
                <summary><ChevronRight size={15} />Exemplo de uso em CI</summary>
                <div className="disclosure-body"><pre className="code-block">{ci}</pre><a className="button secondary compact" href="/ci/egide-github-action.yml" download><ArrowDownToLine size={15} /> Workflow GitHub Actions</a></div>
            </details>
        </section>
        <form className="panel" onSubmit={e => { e.preventDefault(); hookForm.put('/configuracoes/webhook', { preserveScroll: true, preserveState: true, onSuccess: () => hookForm.reset() }); }}>
            <div className="panel-header"><div><h2>Aviso de sessões concluídas</h2><p>Resultado de cada sessão, com destaque para regressões.</p></div>{hasWebhook && <Badge tone="green">Configurado</Badge>}</div>
            <div className="panel-body"><Field label="Webhook HTTPS" error={hookForm.errors.webhook_url} help={hasWebhook ? 'Salve vazio para remover o webhook atual.' : 'Slack, Discord, n8n ou qualquer URL que receba JSON.'}><input type="url" value={hookForm.data.webhook_url} onChange={e => hookForm.setData('webhook_url', e.target.value)} placeholder="https://hooks.slack.com/services/…" /></Field></div>
            <div className="panel-foot"><button className="button primary" disabled={hookForm.processing}><Check size={17} /> Salvar webhook</button></div>
        </form>
        <Dialog open={creating} onClose={() => setCreating(false)} title="Novo token de API" description="O token aparece uma única vez depois de gerado." size="dialog-sm" footer={<>
            <button type="button" className="button secondary" onClick={() => setCreating(false)}>Cancelar</button>
            <button type="submit" form="token-form" className="button primary" disabled={tokenForm.processing}><KeyRound size={16} /> {tokenForm.processing ? 'Gerando…' : 'Gerar token'}</button>
        </>}>
            <form id="token-form" onSubmit={e => { e.preventDefault(); tokenForm.post('/configuracoes/tokens', { preserveScroll: true, preserveState: true, onSuccess: () => { tokenForm.reset(); setCreating(false); } }); }}>
                <Field label="Nome do token" error={tokenForm.errors.name} help="Onde ele será usado."><input required data-autofocus value={tokenForm.data.name} onChange={e => tokenForm.setData('name', e.target.value)} placeholder="GitHub Actions" /></Field>
            </form>
        </Dialog>
        <Dialog open={revealed && !!issuedToken} onClose={() => setRevealed(false)} title="Token gerado" description="Copie agora e guarde como segredo do CI. Ele não será exibido de novo." footer={<button type="button" className="button primary" onClick={() => setRevealed(false)} data-autofocus><Check size={16} /> Já copiei</button>}>
            {issuedToken && <CopyBox value={issuedToken} />}
        </Dialog>
    </div>;
}
export function Settings({ settings, providers, local, hasKey, hasWebhook, tokens = [], issuedToken, apiBase }) {
    const [tab, setTab] = useTab('aba', issuedToken ? 'integracoes' : 'workspace', ['workspace', 'motor', 'integracoes']);
    const form = useForm({ ...settings, model: settings.model ?? '', api_key: '' });
    const save = event => { event.preventDefault(); form.put('/configuracoes', { preserveScroll: true, preserveState: true, onSuccess: () => form.reset('api_key') }); };
    const hosted = form.data.provider !== 'lab' && !local.includes(form.data.provider);
    const foot = <div className="panel-foot"><button className="button primary" disabled={form.processing}><Check size={18} /> {form.processing ? 'Salvando…' : 'Salvar alterações'}</button></div>;
    return <Layout title="Configurações">
        <Heading title="Configurações" description="Workspace, motor de IA e integrações." />
        <Tabs name="config" label="Seções" value={tab} onChange={setTab} className="page-tabs" tabs={[
            { key: 'workspace', label: 'Workspace', icon: LayoutGrid, alert: !!(form.errors.name || form.errors.accent) },
            { key: 'motor', label: 'Motor de IA', icon: ScanLine, alert: !!(form.errors.provider || form.errors.model || form.errors.api_key) },
            { key: 'integracoes', label: 'Integrações', icon: KeyRound, count: tokens.length },
        ]} />
        {tab === 'workspace' && <TabPanel name="config" id="workspace"><form className="panel narrow" onSubmit={save}>
            <div className="panel-header"><div><h2>Workspace</h2><p>Nome e cor exibidos no painel.</p></div></div>
            <div className="panel-body form-stack">
                <Field label="Nome do workspace" error={form.errors.name}><input required value={form.data.name} onChange={e => form.setData('name', e.target.value)} /></Field>
                <div className={'field ' + (form.errors.accent ? 'has-error' : '')}>
                    <label htmlFor="accent">Cor de destaque</label>
                    <div className="color-field"><input id="accent" type="color" value={form.data.accent} onChange={e => form.setData('accent', e.target.value)} /><code>{form.data.accent}</code><button type="button" className="text-link" onClick={() => form.setData('accent', '#6435ea')}>Restaurar padrão</button></div>
                    {form.errors.accent && <small className="field-error" role="alert"><TriangleAlert size={13} />{form.errors.accent}</small>}
                </div>
            </div>
            {foot}
        </form></TabPanel>}
        {tab === 'motor' && <TabPanel name="config" id="motor"><form className="panel narrow" onSubmit={save}>
            <div className="panel-header"><div><h2>Motor de IA</h2><p>A IA escolhe as ações. O executor confirma cada achado no Firefox isolado.</p></div></div>
            <div className="panel-body form-stack">
                <Field label="Provedor" error={form.errors.provider}><select value={form.data.provider} onChange={e => form.setData('provider', e.target.value)}>{Object.entries(providers).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></Field>
                {hosted && <>
                    <Field label="Modelo" error={form.errors.model} help="Identificador do modelo no provedor."><input className="mono-input" value={form.data.model} onChange={e => form.setData('model', e.target.value)} placeholder="claude-sonnet-5-5" /></Field>
                    <Field label="Chave de API" error={form.errors.api_key} help={hasKey && form.data.provider === settings.provider ? 'Há uma chave salva. Deixe vazio para manter.' : 'Fica criptografada no workspace.'}><input type="password" autoComplete="new-password" value={form.data.api_key} onChange={e => form.setData('api_key', e.target.value)} placeholder={hasKey && form.data.provider === settings.provider ? '••••••••••••' : ''} /></Field>
                </>}
            </div>
            {foot}
        </form></TabPanel>}
        {tab === 'integracoes' && <TabPanel name="config" id="integracoes"><Integrations hasWebhook={hasWebhook} tokens={tokens} issuedToken={issuedToken} apiBase={apiBase} /></TabPanel>}
    </Layout>;
}
