import { Link, router } from '@inertiajs/react';
import { ArrowRight, Crosshair } from 'lucide-react';
import { severities, bySeverity } from '../format';
import { Tabs, TabPanel, Empty, Pagination } from '../ui';
import { Layout, Heading } from '../layout';
import { FindingCard } from '../evidence';

export function Findings({ findings, severity = 'todas', counts = {} }) {
    const change = key => router.get('/achados', key === 'todas' ? {} : { severidade: key }, { preserveState: true, preserveScroll: true, replace: true });
    return <Layout title="Achados">
        <Heading title="Achados" description="Falhas confirmadas com evidência de execução." />
        <section className="panel">
            <div className="panel-tabs"><Tabs name="achados" label="Filtrar por severidade" value={severity} onChange={change} tabs={[
                { key: 'todas', label: 'Todos', count: counts.todas },
                ...['critical', 'high', 'medium', 'low'].map(level => ({ key: level, label: severities[level][0], count: counts[level] ?? 0, tone: counts[level] ? severities[level][1] : '' })),
            ]} /></div>
            <TabPanel name="achados" id={severity}>
                {bySeverity(findings.data).map(finding => <FindingCard key={finding.id} finding={finding} link />)}
                {!findings.data.length && <Empty icon={Crosshair} title={severity === 'todas' ? 'Nenhum achado confirmado' : 'Nenhum achado nesta severidade'} action={severity === 'todas' && <Link href="/sessoes" className="text-link">Abrir sessões <ArrowRight size={16} /></Link>}>
                    Os achados aparecem aqui após a validação na sessão.
                </Empty>}
                <Pagination links={findings.links} />
            </TabPanel>
        </section>
    </Layout>;
}
