import { useEffect, useState } from 'react';
import { useForm } from '@inertiajs/react';
import { ArrowDownToLine, Check, ChevronRight, KeyRound, LayoutGrid, Plus, ScanLine, X } from 'lucide-react';
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
export function Settings({ settings, engine, usage, hasWebhook, tokens = [], issuedToken, apiBase }) {
    const [tab, setTab] = useTab('aba', issuedToken ? 'integracoes' : 'workspace', ['workspace', 'motor', 'integracoes']);
    const form = useForm({ name: settings.name });
    const save = event => { event.preventDefault(); form.put('/configuracoes', { preserveScroll: true, preserveState: true }); };
    return <Layout title="Configurações">
        <Heading title="Configurações" description="Workspace, motor de IA e integrações." />
        <Tabs name="config" label="Seções" value={tab} onChange={setTab} className="page-tabs" tabs={[
            { key: 'workspace', label: 'Workspace', icon: LayoutGrid, alert: !!form.errors.name },
            { key: 'motor', label: 'Motor de IA', icon: ScanLine },
            { key: 'integracoes', label: 'Integrações', icon: KeyRound, count: tokens.length },
        ]} />
        {tab === 'workspace' && <TabPanel name="config" id="workspace"><form className="panel narrow" onSubmit={save}>
            <div className="panel-header"><div><h2>Workspace</h2><p>Nome exibido no painel e nos relatórios.</p></div></div>
            <div className="panel-body form-stack">
                <Field label="Nome do workspace" error={form.errors.name}><input required maxLength={60} value={form.data.name} onChange={e => form.setData('name', e.target.value)} /></Field>
            </div>
            <div className="panel-foot"><button className="button primary" disabled={form.processing}><Check size={18} /> {form.processing ? 'Salvando…' : 'Salvar'}</button></div>
        </form></TabPanel>}
        {tab === 'motor' && <TabPanel name="config" id="motor"><section className="panel narrow">
            <div className="panel-header"><div><h2>Motor de IA</h2><p>Fornecido pela plataforma. A IA escolhe as ações e o executor confirma cada achado.</p></div>{engine ? <Badge tone="green">Ativo</Badge> : <Badge>Desligado</Badge>}</div>
            {engine ? <dl className="engine-facts">
                <div><dt>Provedor</dt><dd>{engine.label}</dd></div>
                {engine.model && <div><dt>Modelo</dt><dd className="mono">{engine.model}</dd></div>}
                {usage && <div><dt>Sessões com IA hoje</dt><dd>{usage.used} de {usage.limit}</dd></div>}
            </dl> : <Empty icon={ScanLine} title="Motor de IA ainda não configurado">Enquanto isso, as sessões rodam o roteiro do laboratório.</Empty>}
        </section></TabPanel>}
        {tab === 'integracoes' && <TabPanel name="config" id="integracoes"><Integrations hasWebhook={hasWebhook} tokens={tokens} issuedToken={issuedToken} apiBase={apiBase} /></TabPanel>}
    </Layout>;
}
