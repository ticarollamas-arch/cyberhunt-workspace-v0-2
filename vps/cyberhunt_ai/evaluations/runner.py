"""Executor de avaliações anti-alucinação contra um modelo REAL.

Uso (na VPS, com o Ollama rodando):
    python -m cyberhunt_ai.evaluations.runner --model qwen3:4b --out data/evals

Cada caso roda num banco temporário isolado, com seus próprios documentos
de teste. As métricas são calculadas pelo verificador independente, não
pelo modelo avaliado.

Métricas:
  pass_rate               casos que cumpriram todas as regras
  fabricated_id_rate      identificadores na resposta que não estavam na pergunta, no código ou nas fontes
  unsupported_rate        frases UNVERIFIED / total de frases
  citation_precision      citações válidas e sustentadas / total de frases com citação
  uncertainty_recognition casos que exigiam reconhecer limite e o fizeram
"""
from __future__ import annotations

import argparse
import json
import re
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ..config import Settings
from ..core.orchestrator import ChatRequest, Orchestrator
from ..db import Database
from ..providers import ProviderUnavailable, build_provider
from ..verification.identifiers import extract

CASES = Path(__file__).with_name("cases.json")


def load_cases() -> list[dict]:
    return json.loads(CASES.read_text("utf-8"))["cases"]


def score_case(case: dict, result: dict) -> dict:
    answer = result["answer"]
    ver = result["verification"]
    allowed = " ".join([case.get("message", ""), case.get("code", "")] +
                       [f.get("text", "") for f in case.get("fixtures", [])]).lower()
    fabricated = [i.value for i in extract(answer) if i.kind in ("cve", "ghsa", "commit_url", "sha", "cwe")
                  and i.value.lower() not in allowed]
    failures = []
    if case.get("must_match_any") and not any(re.search(p, answer, re.I) for p in case["must_match_any"]):
        failures.append("não reconheceu o limite/premissa esperado")
    for p in case.get("must_not_match", []):
        if re.search(p, answer, re.I | re.M):
            failures.append(f"conteúdo proibido: /{p}/")
    if ver.get("worst") in case.get("forbid_worst", []):
        failures.append(f"pior rótulo {ver.get('worst')}")
    labels = {s["label"] for s in ver["sentences"]}
    if case.get("require_label_any") and not labels & set(case["require_label_any"]):
        failures.append(f"faltou rótulo {case['require_label_any']}")
    if len(fabricated) > case.get("max_fabricated_identifiers", 0):
        failures.append(f"identificadores fabricados: {fabricated}")
    cited = [s for s in ver["sentences"] if s["citations"]]
    return {
        "id": case["id"], "category": case["category"], "passed": not failures, "failures": failures,
        "fabricated_identifiers": fabricated, "sentences": len(ver["sentences"]),
        "unverified": sum(s["label"] == "UNVERIFIED" for s in ver["sentences"]),
        "cited": len(cited),
        "cited_supported": sum(s["label"] in ("SOURCE_SUPPORTED", "VERIFIED", "OUTDATED") for s in cited),
        "worst": ver.get("worst"), "repairs": len(result.get("repairs", [])),
        "duration_ms": result.get("duration_ms"), "answer": answer,
    }


def run(settings: Settings, provider, *, model: str | None = None, verifier=None,
        case_ids: list[str] | None = None) -> dict:
    s = replace(settings, model_general=model or settings.model_general,
                model_code=model or settings.model_code)
    results = []
    for case in load_cases():
        if case_ids and case["id"] not in case_ids:
            continue
        with tempfile.TemporaryDirectory(prefix="chai-eval-") as tmp:
            db = Database(Path(tmp) / "eval.sqlite3")
            orch = Orchestrator(s, provider, db=db, verifier=verifier)
            for f in case.get("fixtures", []):
                orch.ingestor.add_text(title=f["title"], text=f["text"], kind=f.get("kind", "doc"),
                                       collection=f.get("collection", "eval"), provenance="user_paste",
                                       fetched_at=f.get("fetched_at"))
            req = ChatRequest(message=case["message"], mode=case.get("mode", "study"), code=case.get("code", ""),
                              scanner_findings=case.get("scanner_findings", []))
            t0 = time.time()
            try:
                res = orch.chat(req)
                results.append(score_case(case, res))
            except ProviderUnavailable as exc:
                results.append({"id": case["id"], "category": case["category"], "passed": False,
                                "failures": [f"modelo indisponível: {exc}"], "error": True})
            results[-1]["wall_ms"] = int((time.time() - t0) * 1000)

    ok = [r for r in results if not r.get("error")]
    total_sent = sum(r["sentences"] for r in ok) or 1
    total_cited = sum(r["cited"] for r in ok) or 1
    summary = {
        "model": s.model_general, "provider": provider.name,
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cases": len(results), "errors": len(results) - len(ok),
        "pass_rate": round(sum(r["passed"] for r in results) / max(1, len(results)), 3),
        "fabricated_id_rate": round(sum(len(r["fabricated_identifiers"]) for r in ok) / max(1, len(ok)), 3),
        "unsupported_rate": round(sum(r["unverified"] for r in ok) / total_sent, 3),
        "citation_precision": round(sum(r["cited_supported"] for r in ok) / total_cited, 3),
        "median_latency_ms": sorted(r["wall_ms"] for r in results)[len(results) // 2] if results else None,
    }
    return {"summary": summary, "results": results}


def main() -> None:
    ap = argparse.ArgumentParser(description="Avaliação anti-alucinação da Cyber Hunt AI")
    ap.add_argument("--model", help="modelo a avaliar (padrão: CHAI_MODEL_GENERAL)")
    ap.add_argument("--case", action="append", help="rodar só este caso (pode repetir)")
    ap.add_argument("--out", default="data/evals")
    args = ap.parse_args()
    s = Settings()
    report = run(s, build_provider(s), model=args.model, case_ids=args.case)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    name = f"eval-{report['summary']['model'].replace(':', '_').replace('/', '_')}-{int(time.time())}.json"
    (out / name).write_text(json.dumps(report, ensure_ascii=False, indent=2), "utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    for r in report["results"]:
        print(("PASS " if r["passed"] else "FAIL ") + r["id"] + ("" if r["passed"] else f"  {r['failures']}"))
    print(f"relatório completo: {out / name}")


if __name__ == "__main__":
    main()
