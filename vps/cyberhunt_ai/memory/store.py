"""Memória persistente e privada, organizada por categoria.

Regras de escrita:
- Só a pesquisadora grava memória (diretamente ou confirmando uma sugestão).
- O modelo pode SUGERIR memórias; a sugestão aparece na interface e só é
  salva com confirmação explícita.
- Tudo pode ser consultado, editado, exportado e excluído.
"""
from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timezone

from ..db import Database

CATEGORIES = ("learning", "professional", "research", "preferences", "corrections")
PROGRESS_STATES = ("not_started", "studying", "practiced", "demonstrated")


def _fts(q: str) -> str:
    t = unicodedata.normalize("NFKD", q.lower())
    t = "".join(c for c in t if not unicodedata.combining(c))
    return " OR ".join(f'"{w}"' for w in dict.fromkeys(re.findall(r"[a-z0-9_]{3,}", t)))[:800]


class MemoryStore:
    def __init__(self, db: Database):
        self.db = db

    # --- memórias ---------------------------------------------------------
    def add(self, category: str, content: str, origin: str = "user") -> dict:
        if category not in CATEGORIES:
            raise ValueError(f"categoria inválida: {category}")
        content = content.strip()
        if not content:
            raise ValueError("conteúdo vazio")
        cur = self.db.execute("INSERT INTO memories(category, content, origin) VALUES (?,?,?)",
                              (category, content[:4000], origin))
        return self.get(cur.lastrowid)

    def get(self, mid: int) -> dict | None:
        return self.db.one("SELECT * FROM memories WHERE id=?", (mid,))

    def update(self, mid: int, content: str) -> dict | None:
        self.db.execute("UPDATE memories SET content=?, updated_at=datetime('now') WHERE id=?",
                        (content.strip()[:4000], mid))
        return self.get(mid)

    def delete(self, mid: int) -> None:
        self.db.execute("DELETE FROM memories WHERE id=?", (mid,))

    def list(self, category: str | None = None) -> list[dict]:
        if category:
            return self.db.query("SELECT * FROM memories WHERE category=? ORDER BY id DESC", (category,))
        return self.db.query("SELECT * FROM memories ORDER BY id DESC")

    def recall(self, question: str, k: int = 5) -> list[dict]:
        """Preferências e correções sempre entram; o resto por relevância."""
        always = self.db.query(
            "SELECT * FROM memories WHERE category IN ('preferences','corrections') ORDER BY id DESC LIMIT 12")
        q = _fts(question)
        relevant = []
        if q:
            relevant = self.db.query(
                "SELECT m.* FROM memories_fts f JOIN memories m ON m.id=f.rowid "
                "WHERE memories_fts MATCH ? AND m.category NOT IN ('preferences','corrections') "
                "ORDER BY bm25(memories_fts) LIMIT ?", (q, k))
        return always + relevant

    # --- progresso de aprendizado -----------------------------------------
    def set_progress(self, topic: str, status: str, evidence: str = "") -> dict:
        if status not in PROGRESS_STATES:
            raise ValueError(f"estado inválido: {status}")
        # Avançar para "practiced" ou "demonstrated" exige evidência (exercício feito, explicação gravada...).
        if status in ("practiced", "demonstrated") and not evidence.strip():
            raise ValueError("este estado exige evidência: descreva o exercício ou a demonstração")
        self.db.execute(
            "INSERT INTO progress(topic,status,evidence,updated_at) VALUES (?,?,?,datetime('now')) "
            "ON CONFLICT(topic) DO UPDATE SET status=excluded.status, evidence=excluded.evidence, "
            "updated_at=excluded.updated_at", (topic, status, evidence.strip()[:4000]))
        return self.db.one("SELECT * FROM progress WHERE topic=?", (topic,))

    def progress(self) -> list[dict]:
        return self.db.query("SELECT * FROM progress ORDER BY updated_at DESC")

    # --- exportação --------------------------------------------------------
    def export(self) -> dict:
        return {
            "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "memories": self.list(),
            "progress": self.progress(),
            "feedback": self.db.query("SELECT * FROM feedback ORDER BY id"),
        }

    def export_json(self) -> str:
        return json.dumps(self.export(), ensure_ascii=False, indent=2)
