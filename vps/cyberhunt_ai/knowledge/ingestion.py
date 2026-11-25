"""Ingestão de documentos com procedência.

Cada documento guarda: URL, coleção (plataforma), tipo, licença, versão,
SHA-256 do conteúdo, status HTTP, data de coleta e sinais de injection.
Coleções separadas evitam misturar políticas de plataformas diferentes.
"""
from __future__ import annotations

import hashlib
import io
import re
from datetime import datetime, timezone
from html.parser import HTMLParser

from ..db import Database
from ..verification import injection, net

MAX_CHUNK_CHARS = 1200
OVERLAP = 150


class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header", "form"}
    BLOCK = {"p", "div", "li", "h1", "h2", "h3", "h4", "h5", "tr", "br", "section", "article", "pre", "td"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._skip:
            self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        return re.sub(r"\n\s*\n+", "\n\n", raw).strip()


def html_to_text(html: str) -> tuple[str, str]:
    p = _TextExtractor()
    p.feed(html)
    return p.title.strip(), p.text()


def pdf_to_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("pypdf não instalado; instale requirements.txt") from exc
    reader = PdfReader(io.BytesIO(data))
    return "\n\n".join((page.extract_text() or "") for page in reader.pages).strip()


def chunk(text: str, size: int = MAX_CHUNK_CHARS, overlap: int = OVERLAP) -> list[str]:
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    cur = ""
    for p in paras:
        while len(p) > size:  # parágrafo gigante
            chunks.append((cur + "\n\n" + p[:size]).strip() if cur else p[:size])
            cur = ""
            p = p[size - overlap:]
        if len(cur) + len(p) + 2 > size and cur:
            chunks.append(cur)
            cur = cur[-overlap:] + "\n\n" + p
        else:
            cur = (cur + "\n\n" + p).strip()
    if cur:
        chunks.append(cur)
    return chunks


class Ingestor:
    def __init__(self, db: Database, embedder=None):
        self.db = db
        self.embedder = embedder  # callable(list[str]) -> (model, list[vectors]) | None

    def add_text(self, *, title: str, text: str, url: str = "", kind: str = "doc",
                 collection: str = "general", provenance: str = "user_paste",
                 license: str = "", version: str = "", http_status: int | None = None,
                 fetched_at: str | None = None, private: bool = True) -> dict:
        text = text.strip()
        if not text:
            raise ValueError("documento vazio")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        existing = self.db.one("SELECT * FROM documents WHERE sha256=? AND collection=?", (digest, collection))
        if existing:
            return {**existing, "duplicate": True}
        inj = injection.scan(text)
        fetched_at = fetched_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
        cur = self.db.execute(
            "INSERT INTO documents(title,url,kind,collection,license,version,sha256,http_status,fetched_at,"
            "provenance,injection_signals,private) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (title[:300], url, kind, collection, license, version, digest, http_status, fetched_at,
             provenance, ",".join(inj.signals), int(private)))
        doc_id = cur.lastrowid
        pieces = chunk(text)
        vectors: list = [None] * len(pieces)
        model = None
        if self.embedder:
            try:
                model, vectors = self.embedder(pieces)
            except Exception:
                vectors, model = [None] * len(pieces), None  # busca textual continua funcionando
        import numpy as np
        for i, (piece, vec) in enumerate(zip(pieces, vectors)):
            blob = np.asarray(vec, dtype=np.float32).tobytes() if vec is not None else None
            self.db.execute("INSERT INTO chunks(document_id, ord, text, embedding, embed_model) VALUES (?,?,?,?,?)",
                            (doc_id, i, piece, blob, model if blob else None))
        return {"id": doc_id, "title": title, "sha256": digest, "chunks": len(pieces),
                "injection_signals": inj.signals, "duplicate": False, "fetched_at": fetched_at}

    def add_url(self, url: str, *, kind: str = "doc", collection: str = "general",
                license: str = "", fetcher=net.fetch) -> dict:
        r = fetcher(url, max_bytes=8_000_000)
        if r.status != 200:
            raise ValueError(f"{url} respondeu HTTP {r.status}; nada foi ingerido")
        ctype = (r.content_type or "").lower()
        if "pdf" in ctype or url.lower().endswith(".pdf"):
            title, text = url.rsplit("/", 1)[-1], pdf_to_text(r.body)
        elif "html" in ctype or r.body[:200].lstrip().lower().startswith((b"<!doctype", b"<html")):
            title, text = html_to_text(r.text())
        else:
            title, text = url.rsplit("/", 1)[-1], r.text()
        return self.add_text(title=title or url, text=text, url=r.final_url, kind=kind, collection=collection,
                             provenance="official_fetch", license=license, http_status=r.status, private=False)

    def add_file(self, filename: str, data: bytes, *, kind: str = "doc", collection: str = "private") -> dict:
        name = filename.lower()
        if name.endswith(".pdf"):
            text = pdf_to_text(data)
        elif name.endswith((".html", ".htm")):
            _, text = html_to_text(data.decode("utf-8", "replace"))
        else:
            text = data.decode("utf-8", "replace")
        return self.add_text(title=filename, text=text, kind=kind, collection=collection, provenance="user_upload")

    def delete(self, doc_id: int) -> None:
        self.db.execute("DELETE FROM documents WHERE id=?", (doc_id,))

    def list(self) -> list[dict]:
        return self.db.query(
            "SELECT d.id,d.title,d.url,d.kind,d.collection,d.sha256,d.http_status,d.fetched_at,d.provenance,"
            "d.injection_signals,(SELECT COUNT(*) FROM chunks c WHERE c.document_id=d.id) AS chunks "
            "FROM documents d ORDER BY d.id DESC")
