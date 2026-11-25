"""Benchmark de modelos locais candidatos para a SUA VPS.

Mede, para cada modelo instalado no Ollama:
  - avaliação anti-alucinação completa (cases.json)
  - latência mediana
  - memória ocupada pelo modelo carregado (/api/ps)
  - compreensão de código e português (perguntas com resposta verificável por regra)

Uso:
    cd vps && python -m scripts.benchmark_models qwen3:4b gemma3:4b
O resultado vai para data/benchmarks/*.json e uma tabela no terminal.
Escolha o modelo pelos números, não pela popularidade.
"""
from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import replace
from pathlib import Path

from cyberhunt_ai.config import Settings
from cyberhunt_ai.evaluations import runner
from cyberhunt_ai.providers import Message, OllamaProvider

# Perguntas objetivas: a correção é verificada por regex, não por outro modelo.
PROBES = [
    {"id": "code-sqli", "q": "No código Python `cur.execute(\"SELECT * FROM u WHERE id=\" + uid)`, qual é a correção "
     "recomendada? Responda em uma frase.", "expect": r"parametriz|placeholder|\?|%s"},
    {"id": "code-xss", "q": "Em JavaScript, qual propriedade usar no lugar de innerHTML para inserir texto sem "
     "interpretar HTML? Responda só o nome.", "expect": r"textContent|innerText"},
    {"id": "pt-cwe-cve", "q": "Em português, explique em até duas frases a diferença entre CWE e CVE.",
     "expect": r"(fraqueza|categoria|tipo).*(vulnerabilidade|ocorr[êe]ncia|espec[íi]fic)|(vulnerabilidade|espec[íi]fic).*(fraqueza|categoria)"},
    {"id": "instr-json", "q": "Responda apenas com um JSON válido com a chave \"ok\" valendo true. Nada mais.",
     "expect": r"^\s*\{\s*\"ok\"\s*:\s*true\s*\}\s*$"},
]


def bench(model: str, s: Settings, provider: OllamaProvider) -> dict:
    probe_results = []
    for p in PROBES:
        t0 = time.time()
        c = provider.chat(model, [Message("user", p["q"])], temperature=0)
        text = re.sub(r"<think>.*?</think>", "", c.text, flags=re.S).strip()
        probe_results.append({"id": p["id"], "ok": bool(re.search(p["expect"], text, re.I | re.S)),
                              "ms": int((time.time() - t0) * 1000), "answer": text[:400]})
    loaded = {m.get("name"): m for m in provider.loaded_models()}
    mem = loaded.get(model, {}).get("size")
    ev = runner.run(replace(s, model_general=model), provider, model=model)
    return {"model": model, "memory_bytes": mem, "probes": probe_results,
            "probe_accuracy": sum(r["ok"] for r in probe_results) / len(probe_results),
            "eval": ev["summary"], "eval_results": ev["results"]}


def main(models: list[str]) -> None:
    s = Settings()
    provider = OllamaProvider(s.ollama_url, keep_alive="1m", timeout=s.request_timeout)
    installed = {m["name"] for m in provider.list_models()}
    out = Path(s.data_dir) / "benchmarks"
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for model in models:
        if model not in installed:
            print(f"pulando {model}: não instalado (ollama pull {model})")
            continue
        print(f"avaliando {model}...")
        r = bench(model, s, provider)
        (out / f"{model.replace(':', '_').replace('/', '_')}-{int(time.time())}.json").write_text(
            json.dumps(r, ensure_ascii=False, indent=2), "utf-8")
        rows.append(r)
    print(f"\n{'modelo':<24}{'RAM':>8}{'probes':>8}{'evals':>8}{'id_fab':>8}{'sem_fonte':>10}{'lat_ms':>9}")
    for r in rows:
        e = r["eval"]
        ram = f"{r['memory_bytes'] / 1e9:.1f}G" if r["memory_bytes"] else "?"
        print(f"{r['model']:<24}{ram:>8}{r['probe_accuracy']:>8.0%}{e['pass_rate']:>8.0%}"
              f"{e['fabricated_id_rate']:>8}{e['unsupported_rate']:>10.0%}{e['median_latency_ms'] or 0:>9}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("uso: python -m scripts.benchmark_models modelo1 [modelo2 ...]")
    main(sys.argv[1:])
