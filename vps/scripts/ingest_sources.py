"""Ingere as fontes oficiais do manifesto knowledge/sources.json.

Uso (na VPS):
    cd vps && python -m scripts.ingest_sources ../knowledge/sources.json

Rode periodicamente (ex.: timer semanal) para renovar a data de coleta;
documentos de política com coleta antiga são rotulados OUTDATED.
Conteúdo alterado gera novo SHA-256 e entra como documento novo.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cyberhunt_ai.config import Settings
from cyberhunt_ai.core.orchestrator import Orchestrator
from cyberhunt_ai.providers import build_provider


def main(manifest: str) -> int:
    s = Settings()
    s.ensure_dirs()
    orch = Orchestrator(s, build_provider(s))
    data = json.loads(Path(manifest).read_text("utf-8"))
    failures = 0
    for src in data["sources"]:
        try:
            r = orch.ingestor.add_url(src["url"], kind=src.get("kind", "doc"), collection=src["collection"])
            status = "duplicado" if r.get("duplicate") else f"{r['chunks']} trechos"
            warn = f"  ALERTA injection: {r['injection_signals']}" if r.get("injection_signals") else ""
            print(f"OK   [{src['collection']}] {src['url']} -> {status}{warn}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL [{src['collection']}] {src['url']} -> {exc}")
    print(f"\n{len(data['sources']) - failures} ingeridas, {failures} falharam.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "../knowledge/sources.json"))
