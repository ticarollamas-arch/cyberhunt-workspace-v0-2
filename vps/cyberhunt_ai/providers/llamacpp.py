"""Provedor llama.cpp (llama-server, API compatível com OpenAI em /v1).

Útil quando se quer controle fino de quantização GGUF sem o Ollama.
Um llama-server carrega um único modelo; o nome do modelo é informativo.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .base import Completion, Message, ProviderUnavailable


class LlamaCppProvider:
    name = "llamacpp"

    def __init__(self, base_url: str, *, timeout: int = 300):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def _req(self, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST" if payload is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            raise ProviderUnavailable(f"llama.cpp HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise ProviderUnavailable(f"llama.cpp inacessível em {self.base}: {exc}") from exc

    def chat(self, model: str, messages: list[Message], *, temperature: float = 0.2,
             num_ctx: int | None = None) -> Completion:
        t0 = time.time()
        payload = {"model": model, "temperature": temperature,
                   "messages": [{"role": m.role, "content": m.content} for m in messages]}
        data = self._req("/v1/chat/completions", payload)
        usage = data.get("usage", {})
        return Completion(text=data["choices"][0]["message"]["content"], model=model, provider=self.name,
                          prompt_tokens=usage.get("prompt_tokens"),
                          completion_tokens=usage.get("completion_tokens"),
                          duration_ms=int((time.time() - t0) * 1000))

    def embed(self, model: str, texts: list[str]) -> list[list[float]]:
        data = self._req("/v1/embeddings", {"model": model, "input": texts})
        return [d["embedding"] for d in data.get("data", [])]

    def list_models(self) -> list[dict]:
        return self._req("/v1/models").get("data", [])

    def model_capabilities(self, model: str) -> set[str]:
        return {"completion"}

    def health(self) -> dict:
        try:
            return {"ok": True, "provider": self.name, "models": [m.get("id") for m in self.list_models()]}
        except ProviderUnavailable as exc:
            return {"ok": False, "provider": self.name, "error": str(exc)}
