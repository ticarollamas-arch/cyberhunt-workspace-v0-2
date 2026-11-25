// Autenticação de usuária única para a área privada.
// - Senha guardada só como hash scrypt em AUTH_PASSWORD_HASH (gere com scripts/hash-password.mjs).
// - Sessão em cookie HttpOnly, Secure, SameSite=Strict, assinado com HMAC-SHA256 (SESSION_SECRET).
import { createHmac, scryptSync, timingSafeEqual, randomBytes } from 'node:crypto';

export const COOKIE = 'chl_session';
const MAX_AGE = 60 * 60 * 12; // 12 h

export function hashPassword(password, { N = 16384, r = 8, p = 1 } = {}) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 32, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifyPassword(password, stored) {
  if (typeof password !== 'string' || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, hashB64] = parts;
  const expected = Buffer.from(hashB64, 'base64');
  const got = scryptSync(password, Buffer.from(saltB64, 'base64'), expected.length,
    { N: Number(N), r: Number(r), p: Number(p) });
  return got.length === expected.length && timingSafeEqual(got, expected);
}

function sign(payload, secret) {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

export function createSession(secret, now = Date.now()) {
  if (!secret || secret.length < 32) throw new Error('SESSION_SECRET ausente ou curto');
  const payload = Buffer.from(JSON.stringify({ sub: 'owner', exp: Math.floor(now / 1000) + MAX_AGE,
    n: randomBytes(8).toString('hex') })).toString('base64url');
  return `${payload}.${sign(payload, secret)}`;
}

export function readSession(token, secret, now = Date.now()) {
  if (!token || !secret) return null;
  const [payload, mac] = String(token).split('.');
  if (!payload || !mac) return null;
  const expected = Buffer.from(sign(payload, secret));
  const given = Buffer.from(mac);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Math.floor(now / 1000) ? data : null;
  } catch { return null; }
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function sessionCookie(value, maxAge = MAX_AGE) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

// Bloqueia requisições de outra origem em métodos que alteram estado (defesa extra contra CSRF).
export function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // navegadores sempre enviam Origin em POST cross-site
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

export function isAuthenticated(req, env = process.env) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  return Boolean(readSession(token, env.SESSION_SECRET));
}
