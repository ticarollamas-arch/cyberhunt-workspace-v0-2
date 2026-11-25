"""Extração e validação sintática de identificadores verificáveis."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
CWE_RE = re.compile(r"\bCWE-(\d{1,4})\b", re.I)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)
# Commit SHA: 40 hex (SHA-1) ou 64 hex (SHA-256). SHAs curtos são ambíguos e não contam.
SHA_RE = re.compile(r"(?<![0-9a-f])([0-9a-f]{40}|[0-9a-f]{64})(?![0-9a-f])", re.I)
GH_COMMIT_URL_RE = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commit/([0-9a-f]{7,64})", re.I
)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


@dataclass(frozen=True)
class Identifier:
    kind: str   # cve | cwe | ghsa | sha | commit_url | url
    value: str
    syntax_ok: bool = True
    note: str = ""


def extract(text: str) -> list[Identifier]:
    found: dict[tuple[str, str], Identifier] = {}

    for m in CVE_RE.finditer(text):
        year, num = int(m.group(1)), m.group(2)
        value = f"CVE-{m.group(1)}-{num}"
        ok = 1999 <= year <= 2100
        found[("cve", value.upper())] = Identifier("cve", value.upper(), ok, "" if ok else "ano fora do intervalo")
    for m in CWE_RE.finditer(text):
        value = f"CWE-{int(m.group(1))}"
        found[("cwe", value)] = Identifier("cwe", value)
    for m in GHSA_RE.finditer(text):
        found[("ghsa", m.group(0).upper())] = Identifier("ghsa", m.group(0).upper())
    for m in GH_COMMIT_URL_RE.finditer(text):
        value = m.group(0)
        found[("commit_url", value)] = Identifier("commit_url", value)
    for m in SHA_RE.finditer(text):
        found[("sha", m.group(1).lower())] = Identifier("sha", m.group(1).lower())
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:")
        p = urlparse(url)
        ok = bool(p.scheme in ("http", "https") and p.netloc and "." in p.netloc)
        found.setdefault(("url", url), Identifier("url", url, ok, "" if ok else "URL malformada"))
    return list(found.values())


def parse_commit_url(url: str) -> tuple[str, str, str] | None:
    m = GH_COMMIT_URL_RE.match(url)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)
