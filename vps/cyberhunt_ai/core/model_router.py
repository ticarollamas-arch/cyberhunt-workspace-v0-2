"""Escolhe o modelo para cada tarefa e confere capacidades reais.

Em uma VPS de ~8 GB o ideal é ter UM modelo de chat carregado por vez.
O Ollama descarrega modelos ociosos após CHAI_KEEP_ALIVE; use
OLLAMA_MAX_LOADED_MODELS=1 no serviço para impedir carregamento simultâneo.
"""
from __future__ import annotations

from ..config import Settings
from ..providers import ProviderUnavailable

CODE_MODES = {"code_architecture", "patch_learning"}


class CapabilityMissing(ProviderUnavailable):
    pass


class ModelRouter:
    def __init__(self, settings: Settings, provider):
        self.s = settings
        self.provider = provider
        self._caps: dict[str, set[str]] = {}

    def caps(self, model: str) -> set[str]:
        if model not in self._caps:
            self._caps[model] = self.provider.model_capabilities(model)
        return self._caps[model]

    def for_chat(self, mode: str, *, has_images: bool = False) -> str:
        if has_images:
            model = self.s.model_vision
            if not model:
                raise CapabilityMissing("Nenhum modelo de visão configurado (CHAI_MODEL_VISION). "
                                        "A imagem não foi interpretada.")
            caps = self.caps(model)
            if caps and "vision" not in caps:
                raise CapabilityMissing(f"O modelo {model} não declara capacidade de visão.")
            return model
        if mode in CODE_MODES and self.s.model_code:
            return self.s.model_code
        return self.s.model_general

    def embedder(self):
        if not self.s.model_embed:
            return None
        model = self.s.model_embed

        def _embed(texts: list[str]):
            return model, self.provider.embed(model, texts)
        return _embed
