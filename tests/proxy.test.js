import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { createSession, hashPassword, readSession, verifyPassword, COOKIE } from '../lib/session.js';
import aiHandler, { buildTarget } from '../api/ai.js';
import authHandler from '../api/auth.js';

const SECRET = 's'.repeat(48);
let upstream, seen = [];

function mockReq({ method = 'GET', query = {}, headers = {}, body = '' } = {}) {
  const r = Readable.from(body ? [Buffer.from(body)] : []);
  Object.assign(r, { method, query, headers: { host: 'lab.test', ...headers }, url: '/api/x' });
  return r;
}
function mockRes() {
  const res = { code: 200, headers: {}, body: null,
    status(c) { this.code = c; return this; },
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    json(o) { this.body = o; return this; },
    send(b) { this.body = b; return this; } };
  return res;
}

before(async () => {
  upstream = createServer((req, res) => {
    let data = ''; req.on('data', (c) => { data += c; });
    req.on('end', () => { seen.push({ url: req.url, auth: req.headers.authorization, method: req.method, data });
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ ok: true })); });
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  process.env.VPS_URL = `http://127.0.0.1:${upstream.address().port}`;
  process.env.VPS_TOKEN = 'vps-token-secreto';
  process.env.SESSION_SECRET = SECRET;
  process.env.AUTH_PASSWORD_HASH = hashPassword('senha-muito-boa-123', { N: 1024 });
});
after(() => upstream.close());

test('password hash roundtrip', () => {
  const h = hashPassword('abc-def-ghi-jkl', { N: 1024 });
  assert.ok(verifyPassword('abc-def-ghi-jkl', h));
  assert.ok(!verifyPassword('errada', h));
  assert.ok(!verifyPassword('x', 'lixo'));
});

test('session signature and expiry', () => {
  const t = createSession(SECRET);
  assert.equal(readSession(t, SECRET).sub, 'owner');
  assert.equal(readSession(t + 'x', SECRET), null);
  assert.equal(readSession(t, 'o'.repeat(48)), null);
  assert.equal(readSession(createSession(SECRET, Date.now() - 13 * 3600e3), SECRET), null);
});

test('route allowlist', () => {
  assert.equal(buildTarget('http://v', { p: '/etc/passwd' }), null);
  assert.equal(buildTarget('http://v', { p: '/chat', evil: '1', id: '3' }).url.toString(), 'http://v/chat?id=3');
});

test('proxy rejects unauthenticated', async () => {
  const res = mockRes();
  await aiHandler(mockReq({ query: { p: '/health' } }), res);
  assert.equal(res.code, 401);
});

test('login then proxied call carries VPS token server-side only', async () => {
  const bad = mockRes();
  await authHandler(mockReq({ method: 'POST', body: '{"password":"nope"}' }), bad);
  assert.equal(bad.code, 401);

  const ok = mockRes();
  await authHandler(mockReq({ method: 'POST', body: '{"password":"senha-muito-boa-123"}' }), ok);
  assert.equal(ok.code, 200);
  const cookie = ok.headers['set-cookie'];
  assert.match(cookie, /HttpOnly; Secure; SameSite=Strict/);
  const value = cookie.split(';')[0];

  const res = mockRes();
  await aiHandler(mockReq({ method: 'POST', query: { p: '/chat' }, headers: { cookie: value, origin: 'https://lab.test' },
    body: '{"message":"oi"}' }), res);
  assert.equal(res.code, 200);
  const last = seen.at(-1);
  assert.equal(last.url, '/chat');
  assert.equal(last.auth, 'Bearer vps-token-secreto');
  assert.equal(last.data, '{"message":"oi"}');
  assert.ok(!JSON.stringify(res.body).includes('vps-token'));
});

test('cross-origin write blocked', async () => {
  const res = mockRes();
  await aiHandler(mockReq({ method: 'POST', query: { p: '/memory' },
    headers: { cookie: `${COOKIE}=${createSession(SECRET)}`, origin: 'https://evil.example' } }), res);
  assert.equal(res.code, 403);
});

test('method not allowed on route', async () => {
  const res = mockRes();
  await aiHandler(mockReq({ method: 'DELETE', query: { p: '/chat' },
    headers: { cookie: `${COOKIE}=${createSession(SECRET)}` } }), res);
  assert.equal(res.code, 405);
});
