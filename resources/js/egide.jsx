import { createRoot } from 'react-dom/client';
import { createInertiaApp } from '@inertiajs/react';
import '@fontsource-variable/manrope';
import '@fontsource-variable/inter';
import '../css/egide.css';
import { Access } from './egide/pages/access';
import { Overview } from './egide/pages/overview';
import { Assets } from './egide/pages/assets';
import { Sessions, Session } from './egide/pages/sessions';
import { NewSession } from './egide/pages/new-session';
import { Findings } from './egide/pages/findings';
import { Settings } from './egide/pages/settings';
import { Report } from './egide/pages/report';
import { Admin } from './egide/pages/admin';
import { Monitors, MonitorPage } from './egide/pages/sentinel';

const pages = { Access, Overview, Assets, Sessions, Session, NewSession, Findings, Settings, Report, Admin, Monitors, Monitor: MonitorPage };
createInertiaApp({
    title: title => title + ' · Égide AI',
    resolve: name => pages[name],
    setup({ el, App, props }) { createRoot(el).render(<App {...props} />); },
    progress: { color: '#6435ea' },
});
