import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';

export function sentinela({
  key,
  endpoint,
  loginPaths = ['/login', '/api/login', '/api/auth/login'],
  identifier = (req) => req.body?.email ?? req.body?.username,
  flushMs = 2000,
} = {}) {
  if (!key || !endpoint) {
    return (req, res, next) => next();
  }
  const queue = [];
  let timer = null;

  const subjectOf = (value) => (typeof value === 'string' && value.trim()
    ? createHmac('sha256', key).update(value.trim().toLowerCase()).digest('hex')
    : undefined);

  const flush = async () => {
    timer = null;
    const events = queue.splice(0, 100);
    if (!events.length) return;
    try {
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${key}` },
        body: JSON.stringify({ events }),
        signal: AbortSignal.timeout(3000),
      });
    } catch {
      // o Sentinela nunca interrompe a aplicação
    }
    if (queue.length) schedule();
  };

  const schedule = () => {
    if (!timer) timer = setTimeout(flush, flushMs);
    timer.unref?.();
  };

  const push = (event) => {
    if (queue.length >= 1000) queue.shift();
    queue.push(event);
    queue.length >= 50 ? flush() : schedule();
  };

  const succeeded = (path, status, res) => {
    if (status >= 200 && status < 300) return true;
    if (status >= 300 && status < 400) {
      const location = String(res.getHeader?.('location') || '').split('?')[0];
      return !loginPaths.some((login) => location.endsWith(login));
    }
    return false;
  };

  return (req, res, next) => {
    res.on('finish', () => {
      try {
        const path = (req.originalUrl || req.url || '/').split('?')[0];
        const status = res.statusCode;
        const ip = req.ip || req.socket?.remoteAddress;
        if (!ip || !isIP(ip)) return;
        if (req.method === 'POST' && loginPaths.includes(path)) {
          let subject;
          try { subject = subjectOf(identifier(req)); } catch { subject = undefined; }
          push({
            type: succeeded(path, status, res) ? 'login_succeeded' : 'login_failed',
            ip, path, status, subject,
          });
        } else if (status === 401 || status === 403) {
          push({ type: 'access_denied', ip, path, status });
        }
      } catch {
        // o Sentinela nunca interrompe a aplicação
      }
    });
    next();
  };
}
