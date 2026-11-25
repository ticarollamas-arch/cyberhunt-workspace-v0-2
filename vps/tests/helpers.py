"""Utilitários EXCLUSIVOS de teste.

ScriptedProvider devolve textos predefinidos para exercitar o pipeline de
verificação de forma determinística. Ele não faz parte do produto e não é
importável a partir de cyberhunt_ai.
"""
from __future__ import annotations

import json

from cyberhunt_ai.config import Settings
from cyberhunt_ai.providers.base import Completion
from cyberhunt_ai.verification import net
from cyberhunt_ai.verification.source_verifier import SourceVerifier


class ScriptedProvider:
    name = "scripted-test"

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def chat(self, model, messages, *, temperature=0.2, num_ctx=None):
        self.calls.append(messages)
        text = self.replies.pop(0) if self.replies else "[DESCONHECIDO] sem roteiro."
        return Completion(text=text, model=model, provider=self.name, duration_ms=1)

    def embed(self, model, texts):
        raise AssertionError("embeddings não usados nos testes")

    def list_models(self):
        return []

    def model_capabilities(self, model):
        return set()

    def health(self):
        return {"ok": True, "provider": self.name}


def fake_fetcher(table: dict):
    """table: url -> (status, body_dict_or_bytes)."""
    def _fetch(url, method="GET", headers=None, timeout=20, max_bytes=5_000_000):
        status, body = table.get(url, (404, b""))
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        return net.Response(status, body, url, "application/json")
    return _fetch


def offline_verifier():
    return SourceVerifier(online=False)


def settings(tmp) -> Settings:
    s = Settings()
    s.data_dir = tmp
    s.api_token = "t" * 40
    s.model_general = "modelo-teste"
    s.model_code = ""
    s.model_vision = ""
    s.model_embed = ""
    s.online_verification = False
    return s
