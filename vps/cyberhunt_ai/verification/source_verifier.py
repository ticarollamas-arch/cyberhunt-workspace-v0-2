"""Verificação independente de identificadores contra fontes autoritativas.

Este módulo NÃO usa o modelo de linguagem. Ele consulta:
  - CVE Services (cveawg.mitre.org) para CVEs
  - OSV (api.osv.dev) para GHSA e como apoio para CVEs
  - API do GitHub para commits
  - Catálogo CWE local (seed ou importado da MITRE)
  - HTTP direto para URLs (com proteção contra SSRF)

Se a verificação online estiver desligada ou falhar, o resultado é
"unknown" — nunca "exists".
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import net
from .cwe_catalog import CweCatalog
from .identifiers import Identifier, parse_commit_url
from .labels import Label

Fetcher = Callable[..., net.Response]


@dataclass
class Check:
    kind: str
    value: str
    status: str            # exists | not_found | rejected | unknown | syntax_error | blocked
    label: Label
    detail: str = ""
    checked_url: str = ""
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["label"] = self.label.value
        return d


def _status_label(status: str) -> Label:
    return {
        "exists": Label.VERIFIED,
        "not_found": Label.CONTRADICTED,
        "rejected": Label.CONTRADICTED,
        "syntax_error": Label.CONTRADICTED,
        "blocked": Label.UNVERIFIED,
    }.get(status, Label.UNVERIFIED)


class SourceVerifier:
    def __init__(self, *, online: bool = True, fetcher: Fetcher | None = None,
                 catalog: CweCatalog | None = None, github_token: str = "", cache_ttl: int = 3600):
        self.online = online
        self.fetch = fetcher or net.fetch
        self.catalog = catalog or CweCatalog()
        self.github_token = github_token
        self.cache_ttl = cache_ttl
        self._cache: dict[tuple[str, str], tuple[float, Check]] = {}

    # ------------------------------------------------------------------
    def verify(self, ident: Identifier) -> Check:
        key = (ident.kind, ident.value)
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < self.cache_ttl:
            return hit[1]
        if not ident.syntax_ok:
            check = Check(ident.kind, ident.value, "syntax_error", Label.CONTRADICTED, ident.note)
        else:
            handler = getattr(self, f"_verify_{ident.kind}", None)
            check = handler(ident) if handler else Check(ident.kind, ident.value, "unknown", Label.UNVERIFIED,
                                                       "tipo sem verificador")
        self._cache[key] = (time.time(), check)
        return check

    def verify_all(self, idents: list[Identifier]) -> list[Check]:
        return [self.verify(i) for i in idents]

    # ------------------------------------------------------------------
    def _offline(self, ident: Identifier) -> Check:
        return Check(ident.kind, ident.value, "unknown", Label.UNVERIFIED, "verificação online desativada")

    def _safe_fetch(self, ident: Identifier, url: str, **kw) -> net.Response | Check:
        try:
            return self.fetch(url, **kw)
        except net.BlockedDestination as exc:
            return Check(ident.kind, ident.value, "blocked", Label.UNVERIFIED, str(exc), url)
        except Exception as exc:  # rede indisponível, timeout etc.
            return Check(ident.kind, ident.value, "unknown", Label.UNVERIFIED, f"falha de rede: {exc}", url)

    def _verify_cve(self, ident: Identifier) -> Check:
        if not self.online:
            return self._offline(ident)
        url = f"https://cveawg.mitre.org/api/cve/{ident.value}"
        r = self._safe_fetch(ident, url, headers={"Accept": "application/json"})
        if isinstance(r, Check):
            return r
        if r.status == 404:
            return Check("cve", ident.value, "not_found", Label.CONTRADICTED, "CVE Services: registro inexistente", url)
        if r.status != 200:
            return Check("cve", ident.value, "unknown", Label.UNVERIFIED, f"HTTP {r.status}", url)
        try:
            meta = json.loads(r.body).get("cveMetadata", {})
        except ValueError:
            return Check("cve", ident.value, "unknown", Label.UNVERIFIED, "resposta não-JSON", url)
        state = str(meta.get("state", "")).upper()
        if state == "REJECTED":
            return Check("cve", ident.value, "rejected", Label.CONTRADICTED, "CVE rejeitado pela CNA", url)
        return Check("cve", ident.value, "exists", Label.VERIFIED,
                     f"estado {state or '?'}; publicado {meta.get('datePublished', '?')}", url)

    def _verify_ghsa(self, ident: Identifier) -> Check:
        if not self.online:
            return self._offline(ident)
        url = f"https://api.osv.dev/v1/vulns/{ident.value}"
        r = self._safe_fetch(ident, url)
        if isinstance(r, Check):
            return r
        if r.status == 404:
            return Check("ghsa", ident.value, "not_found", Label.CONTRADICTED, "OSV: aviso inexistente", url)
        if r.status == 200:
            return Check("ghsa", ident.value, "exists", Label.VERIFIED, "OSV: aviso encontrado", url)
        return Check("ghsa", ident.value, "unknown", Label.UNVERIFIED, f"HTTP {r.status}", url)

    def _verify_cwe(self, ident: Identifier) -> Check:
        num = int(ident.value.split("-")[1])
        entry = self.catalog.lookup(num)
        ref = f"https://cwe.mitre.org/data/definitions/{num}.html"
        if entry:
            return Check("cwe", ident.value, "exists", Label.VERIFIED,
                         f"{entry['name']} (catálogo {entry['origin']})", ref)
        if self.catalog.is_complete():
            return Check("cwe", ident.value, "not_found", Label.CONTRADICTED,
                         "ausente do catálogo oficial importado", ref)
        if not self.online:
            return Check("cwe", ident.value, "unknown", Label.UNVERIFIED,
                         "fora do catálogo seed; importe o catálogo oficial", ref)
        r = self._safe_fetch(ident, ref, method="GET", max_bytes=400_000)
        if isinstance(r, Check):
            return r
        if r.status == 404:
            return Check("cwe", ident.value, "not_found", Label.CONTRADICTED, "página oficial inexistente", ref)
        if r.status == 200:
            return Check("cwe", ident.value, "exists", Label.VERIFIED, "página oficial encontrada", ref)
        return Check("cwe", ident.value, "unknown", Label.UNVERIFIED, f"HTTP {r.status}", ref)

    def _verify_commit_url(self, ident: Identifier) -> Check:
        parsed = parse_commit_url(ident.value)
        if not parsed:
            return Check("commit_url", ident.value, "syntax_error", Label.CONTRADICTED, "URL de commit inválida")
        if not self.online:
            return self._offline(ident)
        owner, repo, sha = parsed
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        r = self._safe_fetch(ident, url, headers=headers)
        if isinstance(r, Check):
            return r
        if r.status in (404, 422):
            return Check("commit_url", ident.value, "not_found", Label.CONTRADICTED,
                         f"GitHub: commit inexistente em {owner}/{repo}", url)
        if r.status == 200:
            try:
                full = json.loads(r.body).get("sha", sha)
            except ValueError:
                full = sha
            return Check("commit_url", ident.value, "exists", Label.VERIFIED, f"commit {full}", url)
        return Check("commit_url", ident.value, "unknown", Label.UNVERIFIED,
                     f"HTTP {r.status} (limite de taxa? configure CHAI_GITHUB_TOKEN)", url)

    def _verify_sha(self, ident: Identifier) -> Check:
        # Um SHA solto não diz a qual repositório pertence: não há como verificar.
        return Check("sha", ident.value, "unknown", Label.UNVERIFIED,
                     "SHA sem repositório associado; use a URL completa do commit")

    def _verify_url(self, ident: Identifier) -> Check:
        if not self.online:
            return self._offline(ident)
        r = self._safe_fetch(ident, ident.value, method="GET", max_bytes=1)
        if isinstance(r, Check):
            return r
        if r.status in (404, 410):
            return Check("url", ident.value, "not_found", Label.CONTRADICTED, f"HTTP {r.status}", ident.value)
        if 200 <= r.status < 400:
            return Check("url", ident.value, "exists", Label.VERIFIED, f"HTTP {r.status}", ident.value)
        return Check("url", ident.value, "unknown", Label.UNVERIFIED, f"HTTP {r.status}", ident.value)
