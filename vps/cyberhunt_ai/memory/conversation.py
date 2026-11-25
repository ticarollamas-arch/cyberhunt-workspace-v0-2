"""Histórico de conversas com suporte a perguntas paralelas.

Uma pergunta paralela abre uma conversa-filha (parent_id) que herda um
resumo curto do contexto principal sem poluí-lo. Ao voltar, a conversa
principal segue intacta.
"""
from __future__ import annotations

import json

from ..db import Database


class ConversationStore:
    def __init__(self, db: Database):
        self.db = db

    def create(self, title: str = "Conversa", mode: str = "study", parent_id: int | None = None) -> dict:
        cur = self.db.execute("INSERT INTO conversations(title, mode, parent_id) VALUES (?,?,?)",
                              (title[:200], mode, parent_id))
        return self.db.one("SELECT * FROM conversations WHERE id=?", (cur.lastrowid,))

    def get(self, cid: int) -> dict | None:
        return self.db.one("SELECT * FROM conversations WHERE id=?", (cid,))

    def list(self) -> list[dict]:
        return self.db.query("SELECT c.*, (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id) AS n "
                             "FROM conversations c ORDER BY c.id DESC LIMIT 200")

    def delete(self, cid: int) -> None:
        self.db.execute("DELETE FROM conversations WHERE id=?", (cid,))

    def add(self, cid: int, role: str, content: str, meta: dict | None = None) -> int:
        cur = self.db.execute("INSERT INTO messages(conversation_id, role, content, meta) VALUES (?,?,?,?)",
                              (cid, role, content, json.dumps(meta or {}, ensure_ascii=False)))
        return cur.lastrowid

    def messages(self, cid: int, limit: int = 200) -> list[dict]:
        rows = self.db.query("SELECT * FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT ?", (cid, limit))
        for r in rows:
            r["meta"] = json.loads(r["meta"] or "{}")
        return list(reversed(rows))

    def window(self, cid: int, max_chars: int = 6000) -> list[dict]:
        """Últimas mensagens que cabem no orçamento de contexto."""
        out, total = [], 0
        for m in reversed(self.messages(cid, limit=40)):
            total += len(m["content"])
            if total > max_chars:
                break
            out.append({"role": m["role"], "content": m["content"]})
        return list(reversed(out))

    def parent_digest(self, cid: int, max_chars: int = 1500) -> str:
        conv = self.get(cid)
        if not conv or not conv["parent_id"]:
            return ""
        msgs = self.window(conv["parent_id"], max_chars=max_chars)
        return "\n".join(f"{m['role']}: {m['content'][:300]}" for m in msgs)
