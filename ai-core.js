// Lógica pura da interface da Cyber Hunt AI (testável em Node, sem DOM).

export const LABEL_ORDER = ['VERIFIED', 'SOURCE_SUPPORTED', 'INFERRED', 'HYPOTHESIS', 'OUTDATED',
  'INSUFFICIENT_EVIDENCE', 'UNVERIFIED', 'CONTRADICTED'];

export const LABEL_PT = {
  VERIFIED: 'Verificado', SOURCE_SUPPORTED: 'Sustentado pela fonte', INFERRED: 'Inferência',
  HYPOTHESIS: 'Hipótese', OUTDATED: 'Possivelmente desatualizado', INSUFFICIENT_EVIDENCE: 'Evidência insuficiente',
  UNVERIFIED: 'Sem fonte', CONTRADICTED: 'Refutado',
};

// Divide a resposta em blocos: código cercado por ``` e parágrafos de texto.
export function splitBlocks(text = '') {
  const out = [];
  const re = /```([\w-]*)\n?([\s\S]*?)```/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(...paragraphs(text.slice(last, m.index)));
    out.push({ type: 'code', lang: m[1] || '', text: m[2].replace(/\n$/, '') });
    last = re.lastIndex;
  }
  if (last < text.length) out.push(...paragraphs(text.slice(last)));
  return out;
}

function paragraphs(chunk) {
  return chunk.split(/\n{2,}/).map((p) => p.trim()).filter(Boolean).map((p) => {
    const h = p.match(/^(#{1,4})\s+(.*)$/);
    if (h && !p.includes('\n')) return { type: 'heading', level: h[1].length, text: h[2] };
    const lines = p.split('\n');
    if (lines.every((l) => /^\s*(?:[-*•]|\d+[.)])\s+/.test(l))) {
      return { type: 'list', ordered: /^\s*\d/.test(lines[0]), items: lines.map((l) => l.replace(/^\s*(?:[-*•]|\d+[.)])\s+/, '')) };
    }
    return { type: 'para', text: p };
  });
}

// Tokeniza uma linha em texto, citações [S#], marcações epistêmicas e **negrito**.
export function inlineTokens(line = '') {
  const re = /(\[S\d+(?:\s*[,;]\s*S\d+)*\])|(\[(?:INFER[ÊE]NCIA|HIP[ÓO]TESE|DESCONHECIDO)\])|(\*\*[^*]+\*\*)|(`[^`]+`)/gi;
  const out = []; let last = 0, m;
  while ((m = re.exec(line))) {
    if (m.index > last) out.push({ type: 'text', text: line.slice(last, m.index) });
    if (m[1]) out.push({ type: 'cite', ids: m[1].slice(1, -1).split(/\s*[,;]\s*/) });
    else if (m[2]) out.push({ type: 'tag', text: m[2].slice(1, -1).toUpperCase() });
    else if (m[3]) out.push({ type: 'bold', text: m[3].slice(2, -2) });
    else out.push({ type: 'code', text: m[4].slice(1, -1) });
    last = re.lastIndex;
  }
  if (last < line.length) out.push({ type: 'text', text: line.slice(last) });
  return out;
}

export function summarize(verification) {
  const counts = verification?.counts || {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return {
    total,
    grounded: verification?.grounded_ratio ?? 0,
    worst: verification?.worst || null,
    items: LABEL_ORDER.filter((k) => counts[k]).map((k) => ({ label: k, name: LABEL_PT[k], n: counts[k] })),
    risky: ['CONTRADICTED', 'UNVERIFIED', 'INSUFFICIENT_EVIDENCE'].some((k) => counts[k]),
  };
}

// Texto para síntese de voz: sem markdown, sem código, sem citações.
export function speakable(text = '') {
  return text.replace(/```[\s\S]*?```/g, ' (bloco de código omitido) ')
    .replace(/\[S\d+(?:\s*[,;]\s*S\d+)*\]/g, '')
    .replace(/[#*`>|]/g, '').replace(/\s+/g, ' ').trim().slice(0, 3500);
}

export const TRACKS = [
  ['Redes', 'Modelo TCP/IP, DNS, roteamento, portas e o que cada camada protege'],
  ['Linux', 'Processos, permissões, usuários, systemd, logs e isolamento'],
  ['Sistemas operacionais', 'Kernel, chamadas de sistema, memória virtual e privilégios'],
  ['Arquitetura de computadores', 'CPU, memória, pilha, heap e por que isso importa para exploração'],
  ['Python', 'Modelo de execução, bibliotecas, ambientes virtuais e armadilhas de segurança'],
  ['JavaScript', 'Event loop, DOM, Node.js, npm e sinks perigosos'],
  ['C e C++', 'Ponteiros, alocação manual, comportamento indefinido e sanitizadores'],
  ['APIs', 'REST, contratos, autenticação, autorização e OWASP API Top 10'],
  ['HTTP', 'Requisição, resposta, cabeçalhos, cookies, cache e CORS'],
  ['TLS', 'Handshake, certificados, cadeia de confiança e erros comuns'],
  ['OAuth', 'Fluxos, PKCE, tokens, escopos e falhas típicas de implementação'],
  ['IAM', 'Identidade, papéis, menor privilégio e políticas em nuvem'],
  ['Cloud Security', 'Responsabilidade compartilhada, rede, segredos e configuração'],
  ['AppSec', 'Ciclo seguro de desenvolvimento, modelagem de ameaças e revisão'],
  ['DevSecOps', 'Segurança no pipeline: SAST, SCA, segredos e assinatura'],
  ['OWASP', 'Top 10, ASVS e como usar os guias como checklist'],
  ['CWE', 'Taxonomia de fraquezas, hierarquia e uso em análise'],
  ['CVE', 'Ciclo de vida de um CVE, CNAs e registros rejeitados'],
  ['CVSS', 'Métricas base, ambientais e limites da pontuação'],
  ['SAST', 'Análise estática: padrões, fluxo de dados e falsos positivos'],
  ['DAST', 'Análise dinâmica e por que só em alvos autorizados'],
  ['SCA', 'Dependências, OSV, versões vulneráveis e alcançabilidade'],
  ['Engenharia de patches', 'Ler diffs, causa raiz, testes de regressão e contribuição'],
  ['Segurança de memória', 'Buffer overflow, use-after-free e mitigações'],
  ['Git e GitHub', 'Commits, diffs, blame, tags, PRs e procedência do código'],
  ['Containers', 'Namespaces, cgroups, imagens e isolamento real'],
  ['Kubernetes', 'Arquitetura, RBAC, admission e superfície de ataque'],
  ['Inteligência artificial', 'LLMs, RAG, prompt injection e avaliação de modelos'],
];
