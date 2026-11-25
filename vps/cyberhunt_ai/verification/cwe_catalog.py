"""Catálogo CWE local.

O conjunto SEED é pequeno e curado manualmente para funcionar offline.
Para o catálogo completo, importe o arquivo oficial da MITRE:

    python -m scripts.import_cwe caminho/para/cwec_vX.Y.xml

O arquivo oficial é publicado em https://cwe.mitre.org/data/downloads.html.
Uma entrada importada sempre prevalece sobre a SEED.
"""
from __future__ import annotations

import json
from pathlib import Path

SEED: dict[int, str] = {
    20: "Improper Input Validation",
    22: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    77: "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    78: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    79: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    89: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    94: "Improper Control of Generation of Code ('Code Injection')",
    95: "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    120: "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    125: "Out-of-bounds Read",
    200: "Exposure of Sensitive Information to an Unauthorized Actor",
    287: "Improper Authentication",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    352: "Cross-Site Request Forgery (CSRF)",
    416: "Use After Free",
    434: "Unrestricted Upload of File with Dangerous Type",
    476: "NULL Pointer Dereference",
    502: "Deserialization of Untrusted Data",
    611: "Improper Restriction of XML External Entity Reference",
    787: "Out-of-bounds Write",
    798: "Use of Hard-coded Credentials",
    862: "Missing Authorization",
    863: "Incorrect Authorization",
    918: "Server-Side Request Forgery (SSRF)",
}


class CweCatalog:
    def __init__(self, imported_path: Path | None = None):
        self.entries: dict[int, dict] = {k: {"name": v, "origin": "seed"} for k, v in SEED.items()}
        self.imported = False
        if imported_path and imported_path.exists():
            data = json.loads(imported_path.read_text("utf-8"))
            for k, v in data.get("weaknesses", {}).items():
                self.entries[int(k)] = {**v, "origin": f"mitre {data.get('version', '?')}"}
            self.imported = True

    def lookup(self, cwe_id: int) -> dict | None:
        return self.entries.get(cwe_id)

    def is_complete(self) -> bool:
        return self.imported
