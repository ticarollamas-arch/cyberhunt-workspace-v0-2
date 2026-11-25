"""Armazenamento persistente em SQLite (arquivo único em CHAI_DATA_DIR).

SQLite foi escolhido para a primeira versão por caber numa VPS de 8 GB sem
serviço extra. A busca textual usa FTS5 (BM25). Embeddings, quando
configurados, ficam como BLOB float32 e são comparados com numpy.
Migrar para PostgreSQL + pgvector é possível sem alterar a API do SDK.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  url TEXT,
  kind TEXT NOT NULL DEFAULT 'doc',          -- doc | policy | code | report | user
  collection TEXT NOT NULL DEFAULT 'general', -- separa plataformas: google-vrp, hackerone, owasp...
  license TEXT,
  version TEXT,
  sha256 TEXT NOT NULL,
  http_status INTEGER,
  fetched_at TEXT NOT NULL,
  provenance TEXT NOT NULL,                  -- official_fetch | user_upload | user_paste
  injection_signals TEXT NOT NULL DEFAULT '',
  private INTEGER NOT NULL DEFAULT 1,
  UNIQUE(sha256, collection)
);

CREATE TABLE IF NOT EXISTS chunks (
  id INTEGER PRIMARY KEY,
  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  ord INTEGER NOT NULL,
  text TEXT NOT NULL,
  embedding BLOB,
  embed_model TEXT
);
CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
  text, content='chunks', content_rowid='id', tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
  INSERT INTO chunks_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
  INSERT INTO chunks_fts(chunks_fts, rowid, text) VALUES('delete', old.id, old.text);
END;

CREATE TABLE IF NOT EXISTS memories (
  id INTEGER PRIMARY KEY,
  category TEXT NOT NULL,   -- learning | professional | research | preferences | corrections
  content TEXT NOT NULL,
  origin TEXT NOT NULL DEFAULT 'user',  -- user | confirmed_suggestion
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
  content, content='memories', content_rowid='id', tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS mem_ai AFTER INSERT ON memories BEGIN
  INSERT INTO memories_fts(rowid, content) VALUES (new.id, new.content);
END;
CREATE TRIGGER IF NOT EXISTS mem_ad AFTER DELETE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, content) VALUES('delete', old.id, old.content);
END;
CREATE TRIGGER IF NOT EXISTS mem_au AFTER UPDATE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, content) VALUES('delete', old.id, old.content);
  INSERT INTO memories_fts(rowid, content) VALUES (new.id, new.content);
END;

CREATE TABLE IF NOT EXISTS conversations (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL DEFAULT 'Conversa',
  mode TEXT NOT NULL DEFAULT 'study',
  parent_id INTEGER REFERENCES conversations(id) ON DELETE SET NULL,  -- perguntas paralelas
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  meta TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS progress (
  id INTEGER PRIMARY KEY,
  topic TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'not_started',  -- not_started | studying | practiced | demonstrated
  evidence TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY,
  message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
  rating TEXT NOT NULL,          -- correct | incorrect | partially
  correction TEXT NOT NULL DEFAULT '',
  reference_url TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def query(self, sql: str, params: tuple | dict = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple | dict = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None
