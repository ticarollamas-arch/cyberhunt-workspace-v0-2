"""Cliente HTTP mínimo e defensivo usado pelos verificadores e pela ingestão.

- Apenas http/https.
- Bloqueia destinos não públicos (proteção contra SSRF), inclusive após redirecionamento.
- Limita tamanho da resposta e tempo.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

USER_AGENT = "CyberHuntAI/0.1 (+https://cyberhuntlab.com.br; verificacao-de-fontes)"


class BlockedDestination(Exception):
    pass


@dataclass
class Response:
    status: int
    body: bytes
    final_url: str
    content_type: str = ""

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def _assert_public(url: str) -> None:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise BlockedDestination(f"esquema ou host inválido: {url}")
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise BlockedDestination(f"DNS não resolveu {p.hostname}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise BlockedDestination(f"destino não público bloqueado: {p.hostname} -> {ip}")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        _assert_public(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_SafeRedirect())


def fetch(url: str, *, method: str = "GET", headers: dict | None = None,
          timeout: int = 20, max_bytes: int = 5_000_000) -> Response:
    _assert_public(url)
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes + 1)[:max_bytes] if method != "HEAD" else b""
            return Response(resp.status, body, resp.geturl(), resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as exc:
        body = exc.read(min(max_bytes, 200_000)) if exc.fp else b""
        return Response(exc.code, body, url, exc.headers.get("Content-Type", "") if exc.headers else "")
