"""Validação de fundamentação: compara cada frase da resposta com as fontes.

Funciona independentemente do modelo principal. Regras:

1. Frases marcadas [INFERÊNCIA] -> INFERRED; [HIPÓTESE] -> HYPOTHESIS;
   [DESCONHECIDO] -> lacuna declarada (INSUFFICIENT_EVIDENCE, sem penalidade).
2. Frases com citação [S#]:
   - citação para fonte inexistente -> UNVERIFIED (citação fabricada)
   - identificadores/números ausentes da fonte citada e não verificados -> INSUFFICIENT_EVIDENCE
   - sobreposição lexical baixa com a fonte -> INSUFFICIENT_EVIDENCE
   - fonte de política mais velha que o limite -> OUTDATED
   - caso contrário -> SOURCE_SUPPORTED
3. Frases sem citação nem marcação -> UNVERIFIED.
4. Qualquer identificador que o verificador independente refutou -> CONTRADICTED.
5. Identificadores confirmados pelo verificador elevam a frase a VERIFIED
   somente se ela também estiver sustentada pela fonte (não basta o CVE existir).

A sobreposição lexical é uma heurística: ela detecta afirmações sem
lastro, mas não prova que a fonte diz exatamente o mesmo. Por isso o
rótulo é SOURCE_SUPPORTED e não VERIFIED.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .identifiers import extract
from .labels import SEVERITY, Label
from .source_verifier import Check

CITE_RE = re.compile(r"\[(S\d+(?:\s*[,;]\s*S\d+)*)\]")
TAG_RE = re.compile(r"\[(INFER[ÊE]NCIA|INFERENCE|HIP[ÓO]TESE|HYPOTHESIS|DESCONHECIDO|UNKNOWN)\]", re.I)
NUMBER_RE = re.compile(r"(?<![\w.])(?:US\$|R\$|\$)?\s?\d[\d.,]*\s?%?")

STOP = set("""
a o os as um uma uns umas de do da dos das em no na nos nas por para com sem sob sobre entre e ou mas
que se nao não é ser são foi era estar está estão isso isto esse essa este esta aquele aquela como mais
menos muito pouco também tambem já ja ainda quando onde qual quais seu sua seus suas ele ela eles elas
the a an of to in on for with without and or but is are was were be been it this that these those as
by from at into than then so such can may might will would should could not no yes its their there
""".split())


def _norm(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in text if not unicodedata.combining(c))


def content_words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9_\-]{3,}", _norm(text)) if w not in STOP}


def split_sentences(answer: str) -> list[str]:
    # Remove blocos de código: código não é afirmação factual a ser rotulada.
    no_code = re.sub(r"```.*?```", " ", answer, flags=re.S)
    parts: list[str] = []
    for line in no_code.splitlines():
        line = re.sub(r"^\s*(?:[-*•]|\d+[.)])\s+", "", line).strip()
        if not line or line.startswith("#"):
            continue
        parts.extend(s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-ZÁÉÍÓÚÂÊÔÃÕÇ\[])", line) if s.strip())
    return [p for p in parts if len(content_words(p)) >= 3]


@dataclass
class Source:
    id: str
    text: str
    title: str = ""
    url: str = ""
    kind: str = "doc"          # doc | policy | code | user | memory
    fetched_at: str = ""       # ISO-8601
    suspicious: bool = False


@dataclass
class SentenceVerdict:
    text: str
    label: Label
    citations: list[str] = field(default_factory=list)
    support: float | None = None
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"text": self.text, "label": self.label.value, "citations": self.citations,
                "support": None if self.support is None else round(self.support, 2), "issues": self.issues}


@dataclass
class ValidationReport:
    sentences: list[SentenceVerdict]
    checks: list[Check]
    warnings: list[str]

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self.sentences:
            out[s.label.value] = out.get(s.label.value, 0) + 1
        return out

    @property
    def grounded_ratio(self) -> float:
        if not self.sentences:
            return 0.0
        ok = sum(1 for s in self.sentences if s.label in (Label.VERIFIED, Label.SOURCE_SUPPORTED))
        return ok / len(self.sentences)

    @property
    def worst(self) -> Label | None:
        if not self.sentences:
            return None
        return max((s.label for s in self.sentences), key=lambda lb: SEVERITY[lb])

    def to_dict(self) -> dict:
        return {
            "sentences": [s.to_dict() for s in self.sentences],
            "checks": [c.to_dict() for c in self.checks],
            "warnings": self.warnings,
            "counts": self.counts,
            "grounded_ratio": round(self.grounded_ratio, 2),
            "worst": self.worst.value if self.worst else None,
        }


def _age_days(iso: str) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


def validate(answer: str, sources: list[Source], checks: list[Check], *,
             policy_max_age_days: int = 90, support_threshold: float = 0.35) -> ValidationReport:
    by_id = {s.id: s for s in sources}
    check_by_value = {c.value.lower(): c for c in checks}
    verdicts: list[SentenceVerdict] = []
    warnings: list[str] = []

    for sent in split_sentences(answer):
        cites = [c.strip() for grp in CITE_RE.findall(sent) for c in re.split(r"[,;]", grp)]
        tag_m = TAG_RE.search(sent)
        tag = _norm(tag_m.group(1)) if tag_m else ""
        clean = TAG_RE.sub("", CITE_RE.sub("", sent)).strip()
        idents = [i for i in extract(clean) if i.kind != "url"]
        no_ids = clean
        for i in idents:
            no_ids = re.sub(re.escape(i.value), " ", no_ids, flags=re.I)
        no_ids = re.sub(r"https?://\S+", " ", no_ids)
        numbers = [n.strip() for n in NUMBER_RE.findall(no_ids) if len(re.sub(r"\D", "", n)) >= 2]
        v = SentenceVerdict(sent, Label.UNVERIFIED, cites)

        contradicted = [check_by_value[i.value.lower()] for i in idents
                        if i.value.lower() in check_by_value
                        and check_by_value[i.value.lower()].label == Label.CONTRADICTED]

        if tag.startswith("infer"):
            v.label = Label.INFERRED
        elif tag.startswith(("hipo", "hypo")):
            v.label = Label.HYPOTHESIS
        elif tag in ("desconhecido", "unknown"):
            v.label = Label.INSUFFICIENT_EVIDENCE
            v.issues.append("lacuna declarada pelo modelo (comportamento correto)")
        elif cites:
            missing = [c for c in cites if c not in by_id]
            if missing:
                v.issues.append(f"citação para fonte inexistente: {', '.join(missing)}")
                v.label = Label.UNVERIFIED
            else:
                cited = [by_id[c] for c in cites]
                src_text = " ".join(s.text for s in cited)
                src_norm = _norm(src_text)
                words = content_words(clean)
                v.support = len(words & content_words(src_text)) / max(1, len(words))
                absent_ids = [i.value for i in idents if _norm(i.value) not in src_norm]
                absent_nums = [n for n in numbers if re.sub(r"\s", "", n).lower() not in re.sub(r"\s", "", src_norm)]
                if absent_ids:
                    v.issues.append(f"identificador ausente da fonte citada: {', '.join(absent_ids)}")
                if absent_nums:
                    v.issues.append(f"número/valor ausente da fonte citada: {', '.join(absent_nums)}")
                if any(s.suspicious for s in cited):
                    v.issues.append("fonte citada contém sinais de prompt injection")
                if absent_ids or absent_nums or v.support < support_threshold:
                    if v.support < support_threshold:
                        v.issues.append(f"sobreposição baixa com a fonte ({v.support:.0%})")
                    v.label = Label.INSUFFICIENT_EVIDENCE
                else:
                    v.label = Label.SOURCE_SUPPORTED
                    stale = [s for s in cited if s.kind == "policy"
                             and (_age_days(s.fetched_at) or 0) > policy_max_age_days]
                    no_date = [s for s in cited if s.kind == "policy" and _age_days(s.fetched_at) is None]
                    if stale or no_date:
                        v.label = Label.OUTDATED
                        v.issues.append("política sem data recente de coleta; confirme a regra vigente")
                    elif idents and all(check_by_value.get(i.value.lower()) and
                                        check_by_value[i.value.lower()].label == Label.VERIFIED for i in idents):
                        v.label = Label.VERIFIED
        else:
            v.issues.append("afirmação sem fonte" + (" contendo identificador/número" if idents or numbers else
                                                    " (conhecimento do modelo)"))

        if contradicted:
            v.label = Label.CONTRADICTED
            v.issues.extend(f"{c.value}: {c.detail}" for c in contradicted)
        verdicts.append(v)

    if any(v.label == Label.CONTRADICTED for v in verdicts):
        warnings.append("A resposta contém identificadores refutados por verificação independente.")
    risky = [v for v in verdicts if v.label == Label.UNVERIFIED and "identificador" in " ".join(v.issues)]
    if risky:
        warnings.append("Há identificadores ou valores sem fonte; não os use como fato.")
    if verdicts and sum(v.label == Label.UNVERIFIED for v in verdicts) / len(verdicts) > 0.5:
        warnings.append("Mais da metade das afirmações não tem fonte na base de conhecimento.")
    if any(s.suspicious for s in sources):
        warnings.append("Algum documento recuperado contém sinais de prompt injection; foi tratado como dado.")
    return ValidationReport(verdicts, checks, warnings)
