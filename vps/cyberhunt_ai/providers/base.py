"""Interface comum para servidores de modelos locais."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class ProviderUnavailable(Exception):
    """O servidor de modelos não respondeu. Nunca substituir por resposta fixa."""


@dataclass
class Message:
    role: str      # system | user | assistant
    content: str
    images: list[str] = field(default_factory=list)  # base64, apenas para modelos com visão


@dataclass
class Completion:
    text: str
    model: str
    provider: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: int | None = None


class Provider(Protocol):
    name: str

    def chat(self, model: str, messages: list[Message], *, temperature: float = 0.2,
             num_ctx: int | None = None) -> Completion: ...

    def embed(self, model: str, texts: list[str]) -> list[list[float]]: ...

    def list_models(self) -> list[dict]: ...

    def model_capabilities(self, model: str) -> set[str]: ...

    def health(self) -> dict: ...
