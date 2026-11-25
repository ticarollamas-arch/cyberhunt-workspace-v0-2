"""Configuração lida exclusivamente de variáveis de ambiente.

Nenhum segredo fica no código. Veja vps/.env.example.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("CHAI_DATA_DIR", "./data")))
    api_token: str = field(default_factory=lambda: _env("CHAI_API_TOKEN"))

    # Provedor de modelos local: "ollama", "llamacpp" ou "none".
    provider: str = field(default_factory=lambda: _env("CHAI_PROVIDER", "ollama"))
    ollama_url: str = field(default_factory=lambda: _env("CHAI_OLLAMA_URL", "http://127.0.0.1:11434"))
    llamacpp_url: str = field(default_factory=lambda: _env("CHAI_LLAMACPP_URL", "http://127.0.0.1:8080"))

    # Modelos por função. Os nomes são apenas configuração: o benchmark
    # (scripts/benchmark_models.py) decide quais usar na sua VPS.
    model_general: str = field(default_factory=lambda: _env("CHAI_MODEL_GENERAL", "qwen3:4b"))
    model_code: str = field(default_factory=lambda: _env("CHAI_MODEL_CODE", ""))
    model_vision: str = field(default_factory=lambda: _env("CHAI_MODEL_VISION", ""))
    model_embed: str = field(default_factory=lambda: _env("CHAI_MODEL_EMBED", ""))
    # Tempo que o Ollama mantém um modelo na RAM depois do uso.
    keep_alive: str = field(default_factory=lambda: _env("CHAI_KEEP_ALIVE", "5m"))
    num_ctx: int = field(default_factory=lambda: _env_int("CHAI_NUM_CTX", 8192))
    request_timeout: int = field(default_factory=lambda: _env_int("CHAI_TIMEOUT", 300))

    # Multimodal local (binários opcionais).
    whisper_bin: str = field(default_factory=lambda: _env("CHAI_WHISPER_BIN", "whisper-cli"))
    whisper_model: str = field(default_factory=lambda: _env("CHAI_WHISPER_MODEL", ""))
    piper_bin: str = field(default_factory=lambda: _env("CHAI_PIPER_BIN", "piper"))
    piper_voice: str = field(default_factory=lambda: _env("CHAI_PIPER_VOICE", ""))
    ffmpeg_bin: str = field(default_factory=lambda: _env("CHAI_FFMPEG_BIN", "ffmpeg"))
    tesseract_bin: str = field(default_factory=lambda: _env("CHAI_TESSERACT_BIN", "tesseract"))

    # Verificação online de identificadores (CVE, OSV, commits GitHub).
    online_verification: bool = field(default_factory=lambda: _env("CHAI_ONLINE_VERIFY", "1") == "1")
    github_token: str = field(default_factory=lambda: _env("CHAI_GITHUB_TOKEN"))
    # Documentos de política mais antigos que isso viram OUTDATED.
    policy_max_age_days: int = field(default_factory=lambda: _env_int("CHAI_POLICY_MAX_AGE_DAYS", 90))

    cwe_catalog: str = field(default_factory=lambda: _env("CHAI_CWE_CATALOG", ""))

    max_upload_bytes: int = field(default_factory=lambda: _env_int("CHAI_MAX_UPLOAD", 4_000_000))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "cyberhunt_ai.sqlite3"

    @property
    def cwe_catalog_path(self) -> Path:
        return Path(self.cwe_catalog) if self.cwe_catalog else self.data_dir / "cwe_catalog.json"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
