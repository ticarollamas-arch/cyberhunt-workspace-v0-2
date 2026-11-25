// Servidor de desenvolvimento que imita o Vercel: arquivos estáticos + funções em /api.
// Uso: VPS_URL=http://127.0.0.1:8765 VPS_TOKEN=... SESSION_SECRET=... AUTH_PASSWORD_HASH=... node scripts/dev-server.mjs
// Somente para uso local (cookie Secure funciona em http://localhost nos navegadores modernos).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const port = Number(process.env.PORT || 3000);
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };
const vercel = JSON.parse(await readFile(join(root, 'vercel.json'), 'utf8'));
const staticHeaders = vercel.headers[0].headers;
const handlers = { '/api/ai': (await import('../api/ai.js')).default, '/api/auth': (await import('../api/auth.js')).default };
const BLOCKED = /^\/(vps|tests|scripts|knowledge|docs|lib|node_modules)\//;

createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  for (const { key, value } of staticHeaders) res.setHeader(key, value);
  const fn = handlers[url.pathname];
  if (fn) {
    req.query = Object.fromEntries(url.searchParams);
    res.status = (c) => { res.statusCode = c; return res; };
    res.json = (o) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); return res; };
    res.send = (b) => { res.end(b); return res; };
    try { await fn(req, res); } catch (e) { res.statusCode = 500; res.end(String(e)); }
    return;
  }
  let path = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
  if (path === '/' || path === '\\') path = '/index.html';
  if (BLOCKED.test(path) || path.startsWith('/.')) { res.statusCode = 404; return res.end('not found'); }
  try {
    const file = join(root, path);
    if (!file.startsWith(root)) throw new Error('fora da raiz');
    const body = await readFile(file);
    res.setHeader('Content-Type', types[extname(file)] || 'application/octet-stream');
    res.end(body);
  } catch { res.statusCode = 404; res.end('not found'); }
}).listen(port, '127.0.0.1', () => console.log(`Cyber Hunt Lab em http://localhost:${port}`));
