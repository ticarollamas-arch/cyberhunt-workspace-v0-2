// Interface da Cyber Hunt AI. Todo texto vindo do modelo é inserido via textContent (nunca innerHTML).
import { state } from './state.js';
import { LABEL_PT, TRACKS, inlineTokens, speakable, splitBlocks, summarize } from './ai-core.js';

const $ = (id) => document.getElementById(id);
const h = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined) e.append(k instanceof Node ? k : String(k));
  return e;
};

const ui = { conversation: null, parent: null, caps: null, image: null, recorder: null, ready: false };

async function api(path, { method = 'GET', json, raw, ctype, query = {} } = {}) {
  const qs = new URLSearchParams({ p: path, ...query });
  const res = await fetch(`/api/ai?${qs}`, {
    method, credentials: 'same-origin',
    headers: json !== undefined ? { 'Content-Type': 'application/json' } : (ctype ? { 'Content-Type': ctype } : {}),
    body: json !== undefined ? JSON.stringify(json) : raw,
  });
  if (res.status === 401) { showLogin(); throw new Error('Sessão expirada. Entre novamente.'); }
  const type = res.headers.get('content-type') || '';
  const data = type.includes('json') ? await res.json() : await res.blob();
  if (!res.ok) throw new Error(data?.error || `Erro HTTP ${res.status}`);
  return data;
}

// ---------------------------------------------------------------- sessão
function showSetup(vpsOk) {
  $('ai-login').hidden = true; $('ai-app').hidden = true;
  const box = $('ai-setup'); box.hidden = false; box.replaceChildren(
    h('h3', {}, 'A Cyber Hunt AI ainda não foi configurada neste deploy'),
    h('p', {}, 'O site e o scanner funcionam normalmente. A área de IA precisa de quatro variáveis de ambiente no projeto da Vercel (Settings → Environment Variables) e de um novo deploy:'),
    h('ol', {},
      h('li', {}, h('code', {}, 'AUTH_PASSWORD_HASH'), ' e ', h('code', {}, 'SESSION_SECRET'), ' — gere com ', h('code', {}, 'npm run hash-password')),
      h('li', {}, h('code', {}, 'VPS_URL'), ' — endereço HTTPS da API na sua VPS', vpsOk ? ' (já definido)' : ''),
      h('li', {}, h('code', {}, 'VPS_TOKEN'), ' — o valor de CHAI_API_TOKEN da VPS', vpsOk ? ' (já definido)' : '')),
    h('p', { class: 'muted' }, 'Passo a passo completo no README do repositório.'));
  setStatus('Configuração pendente na Vercel.', 'warn');
}

function showLogin() { $('ai-login').hidden = false; $('ai-app').hidden = true; setStatus('Área privada: faça login.', 'warn'); }

async function checkSession() {
  try {
    const r = await fetch('/api/auth', { credentials: 'same-origin' });
    if (!r.ok) throw new Error();
    const { authenticated, configured, vps_configured: vpsOk } = await r.json();
    if (configured === false) return showSetup(vpsOk);
    if (authenticated) await enter(); else showLogin();
  } catch {
    setStatus('As funções /api não responderam. Fora da Vercel use npm run dev; o scanner continua disponível.', 'bad');
  }
}

$('ai-login').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  $('ai-login-msg').textContent = '';
  const r = await fetch('/api/auth', { method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: $('ai-password').value }) });
  $('ai-password').value = '';
  if (r.ok) return enter();
  $('ai-login-msg').textContent = (await r.json().catch(() => ({}))).error || 'Falha no login';
});

$('ai-logout').addEventListener('click', async () => {
  await fetch('/api/auth', { method: 'DELETE', credentials: 'same-origin' });
  showLogin();
});

async function enter() {
  $('ai-login').hidden = true; $('ai-app').hidden = false;
  if (!ui.ready) { buildStatic(); ui.ready = true; }
  await refreshStatus();
  loadConversations(); loadTracks();
}

function setStatus(text, level = 'ok') { const s = $('ai-status'); s.textContent = text; s.dataset.level = level; }

async function refreshStatus() {
  try {
    const [health, caps] = await Promise.all([api('/health'), api('/capabilities')]);
    ui.caps = caps;
    const ms = health.model_server;
    const parts = [ms.ok ? `Modelo: ${caps.models.general} (${ms.provider})` : `Servidor de modelos offline: ${ms.error}`,
      `Voz: ${caps.media.stt ? 'transcrição ok' : 'transcrição indisponível'} / ${caps.media.tts ? 'fala ok' : 'fala indisponível'}`,
      `Visão: ${caps.vision ? caps.models.vision : 'indisponível'}`,
      `OCR: ${caps.media.ocr ? 'ok' : 'indisponível'}`,
      `Verificação online: ${caps.online_verification ? 'ligada' : 'desligada'}`,
      `Catálogo CWE: ${caps.cwe_catalog_complete ? 'oficial importado' : 'seed parcial'}`];
    setStatus(parts.join(' · '), ms.ok ? 'ok' : 'bad');
    $('ai-mic').disabled = !caps.media.stt;
    $('ai-speak').disabled = !caps.media.tts;
    if (!caps.media.tts) $('ai-speak').checked = false;
    $('ai-image').disabled = !caps.vision;
  } catch (e) { setStatus(e.message, 'bad'); }
}

// ---------------------------------------------------------------- estrutura fixa
function buildStatic() {
  const modes = { study: 'Study Mode — aprender', research: 'Research Mode — só com fontes', evidence: 'Evidence Mode — verificar afirmações',
    policy: 'Policy Mode — regras de programas', code_architecture: 'Code Architecture Mode', patch_learning: 'Patch Learning Mode',
    report_analyst: 'Analista de relatórios', communication: 'Communication Mode — 3 versões', interview: 'Interview Mode',
    prompt_engineering: 'Prompt Engineering Mode', voice_tutor: 'Voice Tutor Mode' };
  for (const [k, v] of Object.entries(modes)) $('ai-mode').append(h('option', { value: k }, v));
  for (const b of document.querySelectorAll('[data-ai-tab]')) {
    b.addEventListener('click', () => {
      for (const p of document.querySelectorAll('[data-ai-panel]')) p.hidden = p.dataset.aiPanel !== b.dataset.aiTab;
      for (const x of document.querySelectorAll('[data-ai-tab]')) x.classList.toggle('active', x === b);
      if (b.dataset.aiTab === 'kb') loadDocs();
      if (b.dataset.aiTab === 'memory') loadMemory();
      if (b.dataset.aiTab === 'labels') renderLabels();
    });
  }
}

function renderLabels() {
  const box = $('ai-labels'); box.replaceChildren();
  for (const [k, desc] of Object.entries(ui.caps?.labels || {})) {
    box.append(h('article', { class: 'item' }, h('span', { class: `badge lb-${k}` }, LABEL_PT[k] || k), h('p', {}, desc), h('small', {}, k)));
  }
}

// ---------------------------------------------------------------- conversa
function threadInfo() {
  $('ai-thread-info').textContent = ui.conversation ? `Conversa #${ui.conversation}${ui.parent ? ` (paralela de #${ui.parent})` : ''}` : 'Nova conversa';
  $('ai-parallel').hidden = !ui.conversation || Boolean(ui.parent);
  $('ai-back').hidden = !ui.parent;
}

$('ai-new').addEventListener('click', () => { ui.conversation = null; ui.parent = null; $('ai-thread').replaceChildren(); threadInfo(); });
$('ai-parallel').addEventListener('click', () => {
  ui.parent = ui.conversation; ui.conversation = null; $('ai-thread').replaceChildren(); threadInfo();
  $('ai-thread').append(h('p', { class: 'muted' }, 'Pergunta paralela: o estudo principal fica preservado. Use "Voltar ao estudo principal" ao terminar.'));
  $('ai-input').focus();
});
$('ai-back').addEventListener('click', () => { const p = ui.parent; ui.parent = null; openConversation(p); });

async function loadConversations() {
  try {
    const { conversations } = await api('/conversations');
    const ul = $('ai-convs'); ul.replaceChildren();
    for (const c of conversations.slice(0, 40)) {
      ul.append(h('li', {}, h('button', { type: 'button', class: 'link', onclick: () => openConversation(c.id) },
        `${c.parent_id ? '↳ ' : ''}${c.title}`), h('small', {}, ` ${c.mode} · ${c.n} msgs`)));
    }
  } catch { /* status já mostra o erro */ }
}

async function openConversation(id) {
  const { conversation, messages } = await api('/conversations', { query: { id } });
  ui.conversation = conversation.id; ui.parent = conversation.parent_id;
  $('ai-mode').value = conversation.mode;
  const t = $('ai-thread'); t.replaceChildren();
  for (const m of messages) {
    if (m.role === 'user') t.append(userBubble(m.content));
    else t.append(assistantBubble({ answer: m.content, message_id: m.id, verification: m.meta.verification,
      sources: (m.meta.sources || []).map((s) => ({ ...s, excerpt: (s.text || '').slice(0, 400) })),
      model: m.meta.model, prompt_version: m.meta.prompt_version, repairs: m.meta.repairs, abstained: m.meta.abstained }));
  }
  threadInfo(); t.scrollTop = t.scrollHeight;
}

function userBubble(text) { return h('div', { class: 'msg user' }, h('p', {}, text)); }

function renderInline(line) {
  const p = h('p');
  for (const tok of inlineTokens(line)) {
    if (tok.type === 'text') p.append(tok.text);
    else if (tok.type === 'cite') p.append(h('span', { class: 'cite', title: 'Fonte citada' }, tok.ids.join(', ')));
    else if (tok.type === 'tag') p.append(h('span', { class: `tag tag-${tok.text.slice(0, 4)}` }, tok.text));
    else if (tok.type === 'bold') p.append(h('strong', {}, tok.text));
    else p.append(h('code', {}, tok.text));
  }
  return p;
}

function renderAnswer(text) {
  const box = h('div', { class: 'answer' });
  for (const b of splitBlocks(text)) {
    if (b.type === 'code') {
      box.append(h('div', { class: 'codewrap' }, b.lang === 'mermaid' ? h('small', {}, 'Diagrama (código Mermaid — renderização visual planejada)') : null,
        h('pre', {}, h('code', {}, b.text))));
    } else if (b.type === 'heading') box.append(h(`h${Math.min(6, b.level + 2)}`, {}, b.text));
    else if (b.type === 'list') { const l = h(b.ordered ? 'ol' : 'ul'); for (const it of b.items) l.append(h('li', {}, renderInline(it))); box.append(l); }
    else for (const line of b.text.split('\n')) box.append(renderInline(line));
  }
  return box;
}

function verificationPanel(v) {
  if (!v) return null;
  if (v.abstained) return h('div', { class: 'verify' }, h('span', { class: 'badge lb-INSUFFICIENT_EVIDENCE' }, 'Abstenção'),
    h('small', { class: 'muted' }, ' O modelo não foi chamado porque este modo exige fontes e a base não tem nenhuma relevante.'));
  const s = summarize(v);
  const bar = h('div', { class: 'vbar' }, h('strong', {}, `Fundamentação: ${Math.round(s.grounded * 100)}%`),
    ...s.items.map((i) => h('span', { class: `badge lb-${i.label}` }, `${i.name}: ${i.n}`)));
  const det = h('details', {}, h('summary', {}, 'Verificação frase a frase'));
  for (const sent of v.sentences || []) {
    det.append(h('div', { class: 'vrow' }, h('span', { class: `badge lb-${sent.label}` }, LABEL_PT[sent.label] || sent.label),
      h('span', {}, sent.text), sent.issues?.length ? h('small', {}, sent.issues.join(' · ')) : null));
  }
  if (v.checks?.length) {
    det.append(h('h4', {}, 'Identificadores conferidos fora do modelo'));
    for (const c of v.checks) {
      det.append(h('div', { class: 'vrow' }, h('span', { class: `badge lb-${c.label}` }, c.status), h('code', {}, c.value),
        h('small', {}, `${c.detail}${c.checked_url ? ` — ${c.checked_url}` : ''}`)));
    }
  }
  const warn = (v.warnings || []).map((w) => h('p', { class: 'warn' }, w));
  return h('div', { class: 'verify' }, bar, ...warn, det);
}

function sourcesPanel(sources) {
  if (!sources?.length) return h('p', { class: 'muted' }, 'Nenhuma fonte da base foi usada nesta resposta.');
  const det = h('details', {}, h('summary', {}, `Fontes consultadas (${sources.length})`));
  for (const s of sources) {
    const link = s.url && /^https?:\/\//.test(s.url) ? h('a', { href: s.url, target: '_blank', rel: 'noopener noreferrer' }, s.url) : null;
    det.append(h('div', { class: 'src' }, h('strong', {}, `${s.id} · ${s.title}`),
      h('small', {}, `${s.kind}${s.fetched_at ? ` · coletado ${s.fetched_at.slice(0, 10)}` : ''}${s.suspicious ? ' · ⚠ possível prompt injection' : ''}`),
      link, h('blockquote', {}, s.excerpt || '')));
  }
  return det;
}

function feedbackBox(messageId) {
  if (!messageId) return null;
  const correction = h('textarea', { rows: 2, placeholder: 'Se errou: qual é a informação correta?' });
  const ref = h('input', { type: 'url', placeholder: 'Link da fonte oficial que comprova (opcional)' });
  const msg = h('small');
  const send = async (rating) => {
    try {
      await api('/feedback', { method: 'POST', json: { message_id: messageId, rating, correction: correction.value, reference_url: ref.value } });
      msg.textContent = rating === 'correct' ? 'Registrado como correto.' : 'Correção registrada: ela entrará nas próximas respostas.';
    } catch (e) { msg.textContent = e.message; }
  };
  return h('details', { class: 'feedback' }, h('summary', {}, 'Avaliar esta resposta'),
    h('div', { class: 'actions' }, h('button', { type: 'button', onclick: () => send('correct') }, 'Correta'),
      h('button', { type: 'button', onclick: () => send('partially') }, 'Parcial'),
      h('button', { type: 'button', onclick: () => send('incorrect') }, 'Incorreta')), correction, ref, msg);
}

function suggestionBox(list) {
  if (!list?.length) return null;
  const box = h('div', { class: 'suggest' }, h('strong', {}, 'A IA sugere guardar na memória (nada foi salvo):'));
  for (const sug of list) {
    const row = h('div', { class: 'vrow' }, h('span', { class: 'badge' }, sug.category), h('span', {}, sug.content));
    row.append(h('button', { type: 'button', onclick: async () => {
      try { await api('/memory', { method: 'POST', json: { ...sug, origin: 'confirmed_suggestion' } }); row.replaceChildren(h('small', {}, 'Salvo.')); }
      catch (e) { row.append(h('small', {}, e.message)); }
    } }, 'Salvar'), h('button', { type: 'button', onclick: () => row.remove() }, 'Descartar'));
    box.append(row);
  }
  return box;
}

function assistantBubble(r) {
  const meta = [r.model ? `modelo ${r.model}` : null, r.prompt_version ? `prompt ${r.prompt_version}` : null,
    r.duration_ms ? `${(r.duration_ms / 1000).toFixed(1)} s` : null, r.abstained ? 'abstenção por falta de fonte' : null].filter(Boolean).join(' · ');
  const repairs = r.repairs?.length ? h('p', { class: 'warn' }, `A primeira versão foi reescrita após a verificação independente (${r.repairs[0].before_worst} → ${r.repairs[0].after_worst}).`) : null;
  return h('div', { class: 'msg bot' }, renderAnswer(r.answer), repairs, verificationPanel(r.verification), sourcesPanel(r.sources),
    suggestionBox(r.memory_suggestions), feedbackBox(r.message_id), h('small', { class: 'muted' }, meta));
}

async function send() {
  const message = $('ai-input').value.trim();
  if (!message) return;
  const withCode = $('ai-with-code').checked;
  if (withCode && !state.code) { alert('Rode a Análise de código primeiro para incluir código e alertas.'); return; }
  const body = { message, mode: $('ai-mode').value, conversation_id: ui.conversation, parent_conversation_id: ui.parent,
    code: withCode ? state.code : '', code_origin: withCode ? state.source : '',
    scanner_findings: withCode ? state.findings : [], images: ui.image ? [ui.image] : [] };
  const t = $('ai-thread');
  t.append(userBubble(message));
  const wait = h('div', { class: 'msg bot muted' }, 'Consultando fontes e modelo local… (em CPU pode levar dezenas de segundos)');
  t.append(wait); t.scrollTop = t.scrollHeight;
  $('ai-send').disabled = true; $('ai-input').value = '';
  try {
    const r = await api('/chat', { method: 'POST', json: body });
    ui.conversation = r.conversation_id; threadInfo();
    wait.replaceWith(assistantBubble(r));
    ui.image = null; $('ai-image').value = ''; $('ai-image-name').textContent = '';
    if ($('ai-speak').checked) speak(r.answer);
    loadConversations();
  } catch (e) {
    wait.replaceWith(h('div', { class: 'msg bot error' }, `Sem resposta: ${e.message}. Nenhuma resposta substituta foi gerada.`));
    $('ai-input').value = message;
  } finally { $('ai-send').disabled = false; t.scrollTop = t.scrollHeight; }
}
$('ai-send').addEventListener('click', send);
$('ai-input').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) send(); });

document.addEventListener('chl:study-scan', () => {
  document.querySelector('nav button[data-tab="ai"]').click();
  document.querySelector('[data-ai-tab="chat"]')?.click();
  $('ai-with-code').checked = true;
  $('ai-mode').value = 'study';
  $('ai-input').value = 'Explique os alertas do scanner neste código: o que cada padrão significa, a CWE correspondente, por que um alerta heurístico não confirma vulnerabilidade e como eu testaria localmente.';
});

// ---------------------------------------------------------------- imagem, voz
$('ai-image').addEventListener('change', () => {
  const f = $('ai-image').files[0];
  if (!f) return;
  if (f.size > 3_000_000) { alert('Imagem acima de 3 MB.'); $('ai-image').value = ''; return; }
  const rd = new FileReader();
  rd.onload = () => { ui.image = String(rd.result).split(',')[1]; $('ai-image-name').textContent = f.name; };
  rd.readAsDataURL(f);
});

$('ai-mic').addEventListener('click', async () => {
  const btn = $('ai-mic');
  if (ui.recorder) { ui.recorder.stop(); return; }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const rec = new MediaRecorder(stream); const chunks = [];
    rec.ondataavailable = (e) => chunks.push(e.data);
    rec.onstop = async () => {
      stream.getTracks().forEach((tr) => tr.stop()); ui.recorder = null;
      btn.textContent = 'Transcrevendo…'; btn.setAttribute('aria-pressed', 'false');
      try {
        const blob = new Blob(chunks, { type: rec.mimeType || 'audio/webm' });
        const r = await api('/stt', { method: 'POST', raw: blob, ctype: blob.type });
        $('ai-input').value = ($('ai-input').value + ' ' + r.text).trim();
      } catch (e) { alert(`Transcrição indisponível: ${e.message}`); }
      btn.textContent = 'Microfone';
    };
    rec.start(); ui.recorder = rec; btn.textContent = 'Parar gravação'; btn.setAttribute('aria-pressed', 'true');
  } catch (e) { alert(`Microfone indisponível: ${e.message}`); }
});

async function speak(text) {
  try {
    const wav = await api('/tts', { method: 'POST', json: { text: speakable(text) } });
    const url = URL.createObjectURL(wav);
    const audio = new Audio(url); audio.onended = () => URL.revokeObjectURL(url); audio.play();
  } catch (e) { setStatus(`Voz: ${e.message}`, 'warn'); }
}

// ---------------------------------------------------------------- trilhas
async function loadTracks() {
  let progress = [];
  try { progress = (await api('/learning/progress')).progress; } catch { /* sem backend */ }
  const map = Object.fromEntries(progress.map((p) => [p.topic, p]));
  const box = $('ai-tracks'); box.replaceChildren();
  const statusPt = { not_started: 'não iniciado', studying: 'estudando', practiced: 'praticado', demonstrated: 'demonstrado' };
  for (const [topic, desc] of TRACKS) {
    const cur = map[topic]?.status || 'not_started';
    const evidence = h('textarea', { rows: 2, placeholder: 'Evidência: exercício feito, teste escrito, explicação gravada…' });
    const sel = h('select', {}, ...Object.entries(statusPt).map(([k, v]) => h('option', { value: k, selected: k === cur }, v)));
    const msg = h('small');
    box.append(h('article', { class: 'item' }, h('strong', {}, topic), h('p', {}, desc),
      h('span', { class: `badge st-${cur}` }, statusPt[cur]),
      map[topic]?.evidence ? h('p', { class: 'muted' }, `Evidência: ${map[topic].evidence}`) : null,
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: () => {
          document.querySelector('[data-ai-tab="chat"]').click();
          $('ai-mode').value = 'study'; ui.conversation = null; ui.parent = null; $('ai-thread').replaceChildren(); threadInfo();
          $('ai-input').value = `Ensine ${topic}: ${desc}. Comece pela arquitetura e termine com um exercício local.`;
          api('/learning/progress', { method: 'POST', json: { topic, status: cur === 'not_started' ? 'studying' : cur, evidence: map[topic]?.evidence || '' } }).catch(() => {});
        } }, 'Estudar')),
      h('details', {}, h('summary', {}, 'Registrar progresso'), sel, evidence,
        h('button', { type: 'button', onclick: async () => {
          try { await api('/learning/progress', { method: 'POST', json: { topic, status: sel.value, evidence: evidence.value } }); loadTracks(); }
          catch (e) { msg.textContent = e.message; }
        } }, 'Salvar progresso'), msg)));
  }
}

// ---------------------------------------------------------------- base de conhecimento
async function loadDocs() {
  try {
    const { documents } = await api('/documents');
    const box = $('kb-list'); box.replaceChildren();
    if (!documents.length) box.append(h('p', { class: 'muted' }, 'Base vazia. Sem documentos, os modos Research, Evidence e Policy se abstêm.'));
    for (const d of documents) {
      box.append(h('article', { class: 'item' }, h('strong', {}, d.title),
        h('p', {}, `${d.collection} · ${d.kind} · ${d.chunks} trechos · ${d.provenance} · ${d.fetched_at.slice(0, 10)}${d.http_status ? ` · HTTP ${d.http_status}` : ''}`),
        d.url ? h('a', { href: d.url, target: '_blank', rel: 'noopener noreferrer' }, d.url) : null,
        h('p', {}, h('small', {}, `SHA-256 ${d.sha256}`)),
        d.injection_signals ? h('p', { class: 'warn' }, `Sinais de prompt injection: ${d.injection_signals}`) : null,
        h('button', { type: 'button', onclick: async () => { if (confirm('Remover documento?')) { await api('/documents', { method: 'DELETE', query: { id: d.id } }); loadDocs(); } } }, 'Remover')));
    }
  } catch (e) { $('kb-msg').textContent = e.message; }
}

$('kb-url').addEventListener('submit', async (ev) => {
  ev.preventDefault(); $('kb-msg').textContent = 'Baixando e indexando…';
  try {
    const r = await api('/documents', { method: 'POST', json: { url: $('kb-url-input').value, collection: $('kb-collection').value, kind: $('kb-kind').value } });
    $('kb-msg').textContent = r.duplicate ? 'Conteúdo idêntico já indexado.' : `Indexado: ${r.chunks} trechos.`; loadDocs();
  } catch (e) { $('kb-msg').textContent = e.message; }
});

$('kb-file').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const f = $('kb-file-input').files[0]; if (!f) return;
  if (f.size > 4_000_000) { $('kb-msg').textContent = 'Arquivo acima de 4 MB.'; return; }
  $('kb-msg').textContent = 'Enviando…';
  try {
    const r = await api('/documents', { method: 'POST', raw: f, ctype: f.type || 'application/octet-stream', query: { filename: f.name, kind: $('kb-file-kind').value } });
    $('kb-msg').textContent = `Indexado: ${r.chunks} trechos${r.injection_signals?.length ? ' — atenção: sinais de prompt injection' : ''}.`; loadDocs();
  } catch (e) { $('kb-msg').textContent = e.message; }
});

// ---------------------------------------------------------------- memória
async function loadMemory() {
  try {
    const { memories } = await api('/memory');
    const box = $('mem-list'); box.replaceChildren();
    for (const m of memories) {
      const ta = h('textarea', { rows: 2 }); ta.value = m.content;
      box.append(h('article', { class: 'item' }, h('span', { class: 'badge' }, m.category), h('small', {}, ` ${m.origin} · ${m.updated_at}`), ta,
        h('div', { class: 'actions' },
          h('button', { type: 'button', onclick: async () => { await api('/memory', { method: 'PUT', json: { id: m.id, content: ta.value } }); loadMemory(); } }, 'Salvar edição'),
          h('button', { type: 'button', onclick: async () => { if (confirm('Excluir esta memória?')) { await api('/memory', { method: 'DELETE', query: { id: m.id } }); loadMemory(); } } }, 'Excluir'))));
    }
  } catch (e) { $('mem-list').replaceChildren(h('p', {}, e.message)); }
}

$('mem-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try { await api('/memory', { method: 'POST', json: { category: $('mem-cat').value, content: $('mem-content').value } }); $('mem-content').value = ''; loadMemory(); }
  catch (e) { alert(e.message); }
});

$('mem-export').addEventListener('click', async () => {
  const blob = await api('/memory', { query: { export: '1' } });
  const data = blob instanceof Blob ? blob : new Blob([JSON.stringify(blob, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(data);
  const a = h('a', { href: url, download: 'cyberhunt-memoria.json' }); a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

threadInfo();
checkSession();
