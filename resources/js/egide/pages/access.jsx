import { Head, Link, useForm } from '@inertiajs/react';
import { ArrowRight, CirclePlay } from 'lucide-react';
import { Logo, Field, Orbit } from '../ui';

export function Access({ register, demo }) {
    const form = useForm({ name: '', email: '', password: '' });
    return <div className="access">
        <Head title={register ? 'Criar workspace' : 'Entrar'} />
        <div className="access-copy">
            <Logo />
            <div><h1>Segurança garantida, do teste à correção.</h1><p>Seu time azul com IA: testa, comprova e acompanha a correção.</p></div>
            <Orbit />
        </div>
        <main className="access-form">
            <div className="access-content">
                <div className="mobile-logo"><Logo /></div>
                <h1>{register ? 'Crie seu workspace' : 'Entre na Égide AI'}</h1>
                <p>{register ? 'Configure seu espaço de avaliações.' : 'Acesse suas avaliações e evidências.'}</p>
                <form onSubmit={event => { event.preventDefault(); form.post(register ? '/cadastro' : '/entrar', { onFinish: () => form.reset('password') }); }}>
                    {register && <Field label="Nome" error={form.errors.name}><input autoComplete="name" required value={form.data.name} onChange={e => form.setData('name', e.target.value)} /></Field>}
                    <Field label="E-mail" error={form.errors.email}><input type="email" required autoComplete="email" placeholder="voce@empresa.com.br" value={form.data.email} onChange={e => form.setData('email', e.target.value)} /></Field>
                    <Field label="Senha" error={form.errors.password}><input type="password" required autoComplete={register ? 'new-password' : 'current-password'} value={form.data.password} onChange={e => form.setData('password', e.target.value)} /></Field>
                    <button className="button primary full" disabled={form.processing}>{register ? 'Criar workspace' : 'Entrar'} <ArrowRight size={17} /></button>
                </form>
                {demo && !register && <Link href="/laboratorio/entrar" method="post" as="button" className="button secondary full demo-entry"><CirclePlay size={17} /> Testar no laboratório de demonstração</Link>}
                <p className="access-switch">{register ? 'Já tem acesso?' : 'Novo na Égide AI?'} <Link className="text-link" href={register ? '/entrar' : '/cadastro'}>{register ? 'Entrar' : 'Criar workspace'}</Link></p>
            </div>
        </main>
    </div>;
}
