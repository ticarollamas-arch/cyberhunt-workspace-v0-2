"""Importa o catálogo CWE oficial da MITRE (XML) para data/cwe_catalog.json.

1. Baixe o arquivo em https://cwe.mitre.org/data/downloads.html (cwec_latest.xml.zip) e descompacte.
2. Rode:  cd vps && python -m scripts.import_cwe cwec_v4.xx.xml
3. Ajuste CHAI_CWE_CATALOG se gravar em outro lugar.

Depois disso, um CWE inexistente passa a ser rotulado CONTRADICTED com base
no catálogo oficial, e o CWE Encyclopedia da interface usa os nomes oficiais.
"""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main(xml_path: str, out: str = "data/cwe_catalog.json") -> None:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"c": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    prefix = "c:" if ns else ""
    weaknesses = {}
    for w in root.iter(f"{{{ns['c']}}}Weakness" if ns else "Weakness"):
        desc = w.find(f"{prefix}Description", ns)
        weaknesses[w.get("ID")] = {
            "name": w.get("Name"),
            "abstraction": w.get("Abstraction"),
            "status": w.get("Status"),
            "description": (desc.text or "").strip() if desc is not None else "",
        }
    data = {"version": root.get("Version"), "date": root.get("Date"), "weaknesses": weaknesses}
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(data, ensure_ascii=False, indent=1), "utf-8")
    print(f"{len(weaknesses)} fraquezas importadas (CWE versão {data['version']}) -> {out}")


if __name__ == "__main__":
    main(*sys.argv[1:])
