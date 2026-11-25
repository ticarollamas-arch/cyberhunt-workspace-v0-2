import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inlineTokens, speakable, splitBlocks, summarize, TRACKS } from '../ai-core.js';

test('blocks split code, headings and lists', () => {
  const b = splitBlocks('# Título\n\nTexto [S1].\n\n```js\nx.innerHTML = y\n```\n\n- um\n- dois');
  assert.deepEqual(b.map((x) => x.type), ['heading', 'para', 'code', 'list']);
  assert.equal(b[2].text, 'x.innerHTML = y');
  assert.deepEqual(b[3].items, ['um', 'dois']);
});

test('inline tokens find citations and epistemic tags', () => {
  const t = inlineTokens('[HIPÓTESE] Pode escapar [S1, S2] via `..` e **symlink**.');
  assert.deepEqual(t.filter((x) => x.type !== 'text').map((x) => x.type), ['tag', 'cite', 'code', 'bold']);
  assert.deepEqual(t.find((x) => x.type === 'cite').ids, ['S1', 'S2']);
});

test('html in model output stays text (no markup tokens)', () => {
  const t = inlineTokens('<img src=x onerror=alert(1)>');
  assert.deepEqual(t, [{ type: 'text', text: '<img src=x onerror=alert(1)>' }]);
});

test('summary flags risky answers', () => {
  const s = summarize({ counts: { SOURCE_SUPPORTED: 2, UNVERIFIED: 1 }, grounded_ratio: 0.67, worst: 'UNVERIFIED' });
  assert.equal(s.total, 3); assert.ok(s.risky); assert.equal(s.items[0].label, 'SOURCE_SUPPORTED');
});

test('speakable strips code and citations', () => {
  assert.equal(speakable('Use isto [S1].\n```\nrm -rf\n```'), 'Use isto . (bloco de código omitido)');
});

test('tracks cover the study areas', () => { assert.equal(TRACKS.length, 28); });
