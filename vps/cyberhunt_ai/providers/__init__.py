from __future__ import annotations

from ..config import Settings
from .base import Completion, Message, ProviderUnavailable
from .llamacpp import LlamaCppProvider
from .ollama import OllamaProvider


class NoProvider:
    """Usado quando CHAI_PROVIDER=none. Recusa explicitamente; não simula IA."""
    name = "none"

    def chat(self, *a, **k):
        raise ProviderUnavailable("Nenhum servidor de modelos configurado (CHAI_PROVIDER=none).")

    def embed(self, *a, **k):
        raise ProviderUnavailable("Nenhum servidor de modelos configurado.")

    def list_models(self):
        return []

    def model_capabilities(self, model):
        return set()

    def health(self):
        return {"ok": False, "provider": "none", "error": "CHAI_PROVIDER=none"}


def build_provider(s: Settings):
    if s.provider == "ollama":
        return OllamaProvider(s.ollama_url, keep_alive=s.keep_alive, timeout=s.request_timeout)
    if s.provider == "llamacpp":
        return LlamaCppProvider(s.llamacpp_url, timeout=s.request_timeout)
    return NoProvider()


__all__ = ["Completion", "Message", "ProviderUnavailable", "build_provider",
           "OllamaProvider", "LlamaCppProvider", "NoProvider"]
