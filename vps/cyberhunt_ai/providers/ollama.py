"""Provedor Ollama (API HTTP local, padrão http://127.0.0.1:11434).

Endpoints usados: /api/chat, /api/embed, /api/tags, /api/show, /api/ps.
O servidor deve escutar apenas em 127.0.0.1 na VPS.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .base import Completion, Message, ProviderUnavailable


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str, *, keep_alive: str = "5m", timeout: int = 300):
        self.base = base_url.rstrip("/")
        self.keep_alive = keep_alive
        self.timeout = timeout

    def _post(self, path: str, payload: dict, timeout: int | None = None) -> dict:
        req = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise ProviderUnavailable(f"Ollama HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise ProviderUnavailable(f"Ollama inacessível em {self.base}: {exc}") from exc

    def _get(self, path: str) -> dict:
        try:
            with urllib.request.urlopen(self.base + path, timeout=10) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise ProviderUnavailable(f"Ollama inacessível em {self.base}: {exc}") from exc

    def chat(self, model: str, messages: list[Message], *, temperature: float = 0.2,
             num_ctx: int | None = None) -> Completion:
        msgs = []
        for m in messages:
            d = {"role": m.role, "content": m.content}
            if m.images:
                d["images"] = m.images
            msgs.append(d)
        options = {"temperature": temperature}
        if num_ctx:
            options["num_ctx"] = num_ctx
        t0 = time.time()
        data = self._post("/api/chat", {"model": model, "messages": msgs, "stream": False,
                                        "keep_alive": self.keep_alive, "options": options})
        text = data.get("message", {}).get("content", "")
        # Modelos com "thinking" podem devolver o raciocínio separado; não o exibimos como resposta.
        return Completion(text=text, model=model, provider=self.name,
                          prompt_tokens=data.get("prompt_eval_count"),
                          completion_tokens=data.get("eval_count"),
                          duration_ms=int((time.time() - t0) * 1000))

    def embed(self, model: str, texts: list[str]) -> list[list[float]]:
        data = self._post("/api/embed", {"model": model, "input": texts, "keep_alive": self.keep_alive})
        return data.get("embeddings", [])

    def list_models(self) -> list[dict]:
        return self._get("/api/tags").get("models", [])

    def loaded_models(self) -> list[dict]:
        return self._get("/api/ps").get("models", [])

    def model_capabilities(self, model: str) -> set[str]:
        try:
            data = self._post("/api/show", {"model": model}, timeout=20)
        except ProviderUnavailable:
            return set()
        return set(data.get("capabilities", []) or [])

    def health(self) -> dict:
        try:
            models = self.list_models()
            return {"ok": True, "provider": self.name, "models": [m.get("name") for m in models]}
        except ProviderUnavailable as exc:
            return {"ok": False, "provider": self.name, "error": str(exc)}
