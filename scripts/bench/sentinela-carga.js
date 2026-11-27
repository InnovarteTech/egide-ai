// Carga na ingestão do Sentinela (POST /api/sentinela/eventos).
// Uso: docker run --rm --network host -v "$PWD/scripts/bench:/bench" grafana/k6 run \
//   -e BASE=http://127.0.0.1:8187 -e KEYS=esc_a,esc_b -e RATE=15 -e BATCH=50 /bench/sentinela-carga.js
// Cada chave aceita 600 lotes/min por IP e cada IP 1.200/min; acima disso a API responde 429 de propósito.
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const BASE = __ENV.BASE || 'http://127.0.0.1:8187';
const KEYS = (__ENV.KEYS || '').split(',').filter(Boolean);
const RATE = Number(__ENV.RATE || 15);
const BATCH = Number(__ENV.BATCH || 50);
const DURATION = __ENV.DURATION || '60s';
const TYPES = ['login_failed', 'login_succeeded', 'access_denied', 'password_reset'];
const throttled = new Counter('lotes_limitados_429');

if (KEYS.length === 0) {
  throw new Error('Informe KEYS com uma ou mais chaves esc_ de monitores.');
}

export const options = {
  scenarios: {
    ingestao: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
  thresholds: {
    'http_req_duration{status:202}': ['p(95)<500'],
    checks: ['rate>0.99'],
  },
};

function hex(length) {
  let out = '';
  for (let i = 0; i < length; i++) out += '0123456789abcdef'[Math.floor(Math.random() * 16)];
  return out;
}

function event() {
  return {
    type: TYPES[Math.floor(Math.random() * TYPES.length)],
    ip: `198.51.100.${1 + Math.floor(Math.random() * 254)}`,
    subject: hex(64),
    path: '/entrar',
    status: 401,
  };
}

export default function () {
  const key = KEYS[(__VU + __ITER) % KEYS.length];
  const events = Array.from({ length: BATCH }, event);
  const response = http.post(`${BASE}/api/sentinela/eventos`, JSON.stringify({ events }), {
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Accept: 'application/json' },
  });
  if (response.status === 429) throttled.add(1);
  check(response, {
    'aceito (202)': (r) => r.status === 202,
    'contagem confere': (r) => r.status !== 202 || r.json('accepted') === BATCH,
  });
}
