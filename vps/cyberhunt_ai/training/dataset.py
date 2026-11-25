"""Exporta o feedback da pesquisadora como conjunto de dados para fine-tuning FUTURO.

Isto NÃO treina o modelo. Gera um JSONL no formato de conversas
(system/user/assistant) a partir de:
  - respostas marcadas como corretas (exemplo positivo);
  - respostas marcadas como incorretas/parciais COM correção escrita pela
    pesquisadora (a correção vira a resposta-alvo).

Só faz sentido considerar LoRA/QLoRA quando houver centenas de exemplos
revisados e GPU disponível. Até lá, as correções já influenciam o modelo
via memória da categoria "corrections" (entram em todo prompt).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..db import Database
from ..specialists.prompts import system_prompt


def build(db: Database) -> list[dict]:
    rows = db.query(
        "SELECT f.rating, f.correction, f.reference_url, a.content AS answer, a.meta, a.conversation_id, a.id AS aid "
        "FROM feedback f JOIN messages a ON a.id=f.message_id ORDER BY f.id")
    out = []
    for r in rows:
        q = db.one("SELECT content FROM messages WHERE conversation_id=? AND role='user' AND id<? "
                   "ORDER BY id DESC LIMIT 1", (r["conversation_id"], r["aid"]))
        if not q:
            continue
        mode = json.loads(r["meta"] or "{}").get("mode", "study")
        if r["rating"] == "correct":
            target = r["answer"]
        elif r["correction"].strip():
            target = r["correction"].strip()
        else:
            continue
        out.append({"messages": [{"role": "system", "content": system_prompt(mode)},
                                 {"role": "user", "content": q["content"]},
                                 {"role": "assistant", "content": target}],
                    "meta": {"rating": r["rating"], "reference": r["reference_url"]}})
    return out


def export_jsonl(db: Database, path: Path) -> int:
    rows = build(db)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(rows)
