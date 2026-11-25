// Proxy autenticado: navegador -> /api/ai?p=/chat -> VPS (Bearer VPS_TOKEN).
// O token da VPS existe só nas variáveis de ambiente do Vercel.
import { isAuthenticated, sameOrigin } from '../lib/session.js';

export const ROUTES = {
  '/health': ['GET'],
  '/capabilities': ['GET'],
  '/chat': ['POST'],
  '/verify': ['POST'],
  '/conversations': ['GET', 'DELETE'],
  '/memory': ['GET', 'POST', 'PUT', 'DELETE'],
  '/learning/progress': ['GET', 'POST'],
  '/feedback': ['POST'],
  '/documents': ['GET', 'POST', 'DELETE'],
  '/stt': ['POST'],
  '/tts': ['POST'],
  '/ocr': ['POST'],
};
const PASS_QUERY = new Set(['id', 'category', 'export', 'filename', 'kind', 'collection', 'lang']);
const MAX_BODY = 4_400_000; // limite de corpo das funções do Vercel ~4.5 MB

export function buildTarget(base, query) {
  const path = String(query.p || '');
  if (!ROUTES[path]) return null;
  const url = new URL(base.replace(/\/$/, '') + path);
  for (const [k, v] of Object.entries(query)) if (PASS_QUERY.has(k)) url.searchParams.set(k, String(v));
  return { path, url };
}

async function readRaw(req) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > MAX_BODY) throw new Error('too_large'); chunks.push(c); }
  return Buffer.concat(chunks);
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'faça login para usar a Cyber Hunt AI' });
  if (req.method !== 'GET' && !sameOrigin(req)) return res.status(403).json({ error: 'origem não permitida' });
  const { VPS_URL, VPS_TOKEN } = process.env;
  if (!VPS_URL || !VPS_TOKEN) return res.status(503).json({ error: 'Backend da VPS não configurado (VPS_URL, VPS_TOKEN).' });

  const target = buildTarget(VPS_URL, req.query || Object.fromEntries(new URL(req.url, 'http://x').searchParams));
  if (!target) return res.status(404).json({ error: 'rota desconhecida' });
  if (!ROUTES[target.path].includes(req.method)) return res.status(405).json({ error: 'método não permitido' });

  let body;
  if (!['GET', 'DELETE'].includes(req.method)) {
    try { body = await readRaw(req); } catch { return res.status(413).json({ error: 'arquivo grande demais (máx. ~4 MB)' }); }
  }
  try {
    const upstream = await fetch(target.url, {
      method: req.method,
      headers: { Authorization: `Bearer ${VPS_TOKEN}`,
        'Content-Type': req.headers['content-type'] || 'application/json' },
      body,
      signal: AbortSignal.timeout(295_000),
    });
    const buf = Buffer.from(await upstream.arrayBuffer());
    res.status(upstream.status);
    for (const h of ['content-type', 'content-disposition']) {
      const v = upstream.headers.get(h); if (v) res.setHeader(h, v);
    }
    return res.send(buf);
  } catch (err) {
    return res.status(502).json({ error: `VPS inacessível: ${err.name === 'TimeoutError' ? 'tempo esgotado' : err.message}` });
  }
}
