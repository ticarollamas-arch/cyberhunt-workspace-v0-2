"""Recuperação híbrida: BM25 (FTS5) + similaridade de embeddings (opcional).

Combinação por Reciprocal Rank Fusion, que não exige calibrar escalas
diferentes de pontuação.
"""
from __future__ import annotations

import re
import unicodedata

import numpy as np

from ..db import Database
from ..verification.claim_validator import STOP, Source


def _fts_query(question: str) -> str:
    text = unicodedata.normalize("NFKD", question.lower())
    text = "".join(c for c in text if not unicodedata.combining(c))
    terms = [t for t in re.findall(r"[a-z0-9_]{2,}", text) if t not in STOP]
    # Termos entre aspas evitam que o usuário injete sintaxe FTS.
    return " OR ".join(f'"{t}"' for t in dict.fromkeys(terms))[:1000]


class Retriever:
    def __init__(self, db: Database, embedder=None):
        self.db = db
        self.embedder = embedder

    def search(self, question: str, *, k: int = 6, collections: list[str] | None = None,
               min_bm25_hits: int = 1) -> list[Source]:
        q = _fts_query(question)
        ranked: dict[int, float] = {}
        rows: dict[int, dict] = {}
        coll_sql, params = "", []
        if collections:
            coll_sql = f" AND d.collection IN ({','.join('?' * len(collections))})"
            params = list(collections)

        if q:
            bm = self.db.query(
                "SELECT c.id, c.text, d.title, d.url, d.kind, d.fetched_at, d.injection_signals, d.collection "
                "FROM chunks_fts f JOIN chunks c ON c.id=f.rowid JOIN documents d ON d.id=c.document_id "
                f"WHERE chunks_fts MATCH ?{coll_sql} ORDER BY bm25(chunks_fts) LIMIT 30", (q, *params))
            for rank, r in enumerate(bm):
                ranked[r["id"]] = ranked.get(r["id"], 0) + 1 / (60 + rank)
                rows[r["id"]] = r

        if self.embedder:
            try:
                model, [qv] = self.embedder([question])
                cand = self.db.query(
                    "SELECT c.id, c.text, c.embedding, d.title, d.url, d.kind, d.fetched_at, d.injection_signals, "
                    "d.collection FROM chunks c JOIN documents d ON d.id=c.document_id "
                    f"WHERE c.embedding IS NOT NULL AND c.embed_model=?{coll_sql}", (model, *params))
                if cand:
                    mat = np.stack([np.frombuffer(r["embedding"], dtype=np.float32) for r in cand])
                    qv = np.asarray(qv, dtype=np.float32)
                    sims = mat @ qv / (np.linalg.norm(mat, axis=1) * np.linalg.norm(qv) + 1e-9)
                    for rank, idx in enumerate(np.argsort(-sims)[:30]):
                        if sims[idx] < 0.3:
                            break
                        r = cand[int(idx)]
                        ranked[r["id"]] = ranked.get(r["id"], 0) + 1 / (60 + rank)
                        rows[r["id"]] = r
            except Exception:
                pass  # sem embeddings, segue só com BM25

        best = sorted(ranked, key=lambda i: -ranked[i])[:k]
        out = []
        for n, cid in enumerate(best, start=1):
            r = rows[cid]
            out.append(Source(id=f"S{n}", text=r["text"], title=r["title"], url=r["url"] or "",
                              kind=r["kind"], fetched_at=r["fetched_at"],
                              suspicious=bool(r["injection_signals"])))
        return out
