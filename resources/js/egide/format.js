export const statuses = {
    queued: ['Na fila', 'neutral'],
    running: ['Em execução', 'violet'],
    completed: ['Concluída', 'green'],
    failed: ['Interrompida', 'red'],
    cancelled: ['Encerrada', 'neutral'],
};
export const outcomes = {
    exposure: ['Exposição confirmada', 'red'],
    protected: ['Isolamento confirmado', 'green'],
    mapped: ['Exploração concluída', 'green'],
    challenge: ['Verificação humana encontrada', 'neutral'],
    inconclusive: ['Prova inconclusiva', 'neutral'],
};
export const severities = {
    critical: ['Crítica', 'red'],
    high: ['Alta', 'red'],
    medium: ['Média', 'violet'],
    low: ['Baixa', 'neutral'],
};
export const risks = {
    critical: ['crítico', 'red'],
    high: ['alto', 'red'],
    medium: ['médio', 'violet'],
    low: ['baixo', 'neutral'],
    none: ['sem achados', 'green'],
};
export const verdicts = {
    exposure: 'Uma identidade de teste conseguiu ler um registro que pertence a outra. A falha foi reproduzida com marcadores sintéticos e precisa de correção.',
    protected: 'A aplicação negou o acesso cruzado na rota testada e as duas identidades continuaram acessando seus próprios registros.',
    mapped: 'O agente mapeou a navegação autorizada. As rotas observadas estão listadas abaixo para orientar os próximos testes.',
    challenge: 'A execução encontrou uma verificação humana. Use um ambiente de homologação com acesso de teste liberado.',
    inconclusive: 'A prova não reuniu evidência suficiente para concluir. Confira a atividade registrada.',
};
export function ruleLabel(rule) {
    return rule.method + ' ' + (rule.prefix ? (rule.path === '/' ? '/*' : rule.path + '/*') : rule.path);
}
export function formatDate(value, time = true) {
    if (!value) return '—';
    return new Intl.DateTimeFormat('pt-BR', {
        day: '2-digit', month: 'short', ...(time && { hour: '2-digit', minute: '2-digit' }),
    }).format(new Date(value));
}
export function formatTime(value) {
    return new Date(value).toLocaleTimeString('pt-BR', { hour12: false });
}
export function scanLabel(scan) {
    return 'PT-' + scan.id.slice(-6).toUpperCase();
}
export function hostOf(url) {
    try { return new URL(url).host; } catch { return url ?? ''; }
}
export function plural(count, one, many) {
    return count + ' ' + (count === 1 ? one : many);
}
export function bySeverity(findings) {
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    return findings.slice().sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
}
