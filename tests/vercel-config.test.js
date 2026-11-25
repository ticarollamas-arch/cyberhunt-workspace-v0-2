import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

const v = JSON.parse(readFileSync('vercel.json', 'utf8'));
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const ignore = readFileSync('.vercelignore', 'utf8').split('\n').map((l) => l.trim()).filter(Boolean);

test('functions point to existing files with valid limits', () => {
  for (const [path, cfg] of Object.entries(v.functions)) {
    assert.ok(existsSync(path), `${path} não existe`);
    assert.ok(cfg.maxDuration >= 1 && cfg.maxDuration <= 300, `${path} maxDuration fora do limite`);
  }
});

test('no conflicting legacy keys', () => {
  assert.equal(v.builds, undefined);
  assert.equal(v.routes, undefined);
});

test('node version pinned (no engines auto-upgrade warning)', () => {
  assert.match(pkg.engines.node, /^\d+\.x$/);
  assert.equal(pkg.type, 'module');
});

test('deploy keeps what functions and pages need, drops backend code', () => {
  for (const keep of ['api/', 'lib/', 'assets/']) assert.ok(!ignore.includes(keep), `${keep} não pode ser ignorado`);
  for (const drop of ['vps/', 'tests/']) assert.ok(ignore.includes(drop));
});

test('every local asset referenced by index.html exists', () => {
  const html = readFileSync('index.html', 'utf8');
  const refs = [...html.matchAll(/(?:src|href)="([^"#:]+)"/g)].map((m) => m[1]).filter((r) => !r.startsWith('/') || r === '/');
  for (const r of refs) if (r !== '/') assert.ok(existsSync(r), `referência quebrada: ${r}`);
});

test('CSP allows only same-origin resources', () => {
  const csp = v.headers[0].headers.find((h) => h.key === 'Content-Security-Policy').value;
  assert.match(csp, /connect-src 'self'/);
  assert.match(csp, /img-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
});

test('auth GET reports missing configuration instead of failing', async () => {
  delete process.env.AUTH_PASSWORD_HASH; delete process.env.SESSION_SECRET;
  delete process.env.VPS_URL; delete process.env.VPS_TOKEN;
  const { default: auth } = await import('../api/auth.js?cfg');
  const req = Object.assign(Readable.from([]), { method: 'GET', headers: { host: 'x' } });
  const res = { code: 0, headers: {}, body: null, status(c) { this.code = c; return this; },
    setHeader(k, val) { this.headers[k] = val; }, json(o) { this.body = o; return this; } };
  await auth(req, res);
  assert.equal(res.code, 200);
  assert.deepEqual(res.body, { authenticated: false, configured: false, vps_configured: false });
});
