// Gera AUTH_PASSWORD_HASH e um SESSION_SECRET para as variáveis de ambiente do Vercel.
// Uso: node scripts/hash-password.mjs   (a senha é lida do terminal, sem eco no histórico)
import { createInterface } from 'node:readline';
import { randomBytes } from 'node:crypto';
import { hashPassword } from '../lib/session.js';

const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
rl._writeToOutput = (s) => { if (s.includes('Senha')) process.stdout.write(s); };
rl.question('Senha (mín. 12 caracteres): ', (pw) => {
  rl.close();
  process.stdout.write('\n');
  if (pw.length < 12) { console.error('Senha curta demais.'); process.exit(1); }
  console.log(`AUTH_PASSWORD_HASH=${hashPassword(pw)}`);
  console.log(`SESSION_SECRET=${randomBytes(48).toString('base64url')}`);
});
