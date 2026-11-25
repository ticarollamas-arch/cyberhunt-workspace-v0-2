// POST   /api/auth  {password}  -> inicia sessão
// GET    /api/auth              -> {authenticated}
// DELETE /api/auth              -> encerra sessão
import { createSession, isAuthenticated, sameOrigin, sessionCookie, verifyPassword } from '../lib/session.js';

const attempts = new Map(); // limitação simples por instância; complemente com regras de firewall do Vercel

async function readJson(req, limit = 4096) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > limit) throw new Error('corpo grande'); chunks.push(c); }
  return JSON.parse(Buffer.concat(chunks).toString() || '{}');
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET') return res.status(200).json({ authenticated: isAuthenticated(req) });
  if (!sameOrigin(req)) return res.status(403).json({ error: 'origem não permitida' });
  if (req.method === 'DELETE') {
    res.setHeader('Set-Cookie', sessionCookie('', 0));
    return res.status(200).json({ ok: true });
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'método não suportado' });

  const { AUTH_PASSWORD_HASH, SESSION_SECRET } = process.env;
  if (!AUTH_PASSWORD_HASH || !SESSION_SECRET) {
    return res.status(503).json({ error: 'Autenticação não configurada no Vercel (AUTH_PASSWORD_HASH, SESSION_SECRET).' });
  }
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'local';
  const rec = attempts.get(ip) || { n: 0, until: 0 };
  if (Date.now() < rec.until) return res.status(429).json({ error: 'muitas tentativas; aguarde' });

  let body;
  try { body = await readJson(req); } catch { return res.status(400).json({ error: 'JSON inválido' }); }
  if (!verifyPassword(String(body.password || ''), AUTH_PASSWORD_HASH)) {
    rec.n += 1; if (rec.n >= 5) { rec.until = Date.now() + 15 * 60 * 1000; rec.n = 0; }
    attempts.set(ip, rec);
    return res.status(401).json({ error: 'senha incorreta' });
  }
  attempts.delete(ip);
  res.setHeader('Set-Cookie', sessionCookie(createSession(SESSION_SECRET)));
  return res.status(200).json({ ok: true });
}
