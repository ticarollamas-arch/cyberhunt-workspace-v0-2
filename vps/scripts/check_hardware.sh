#!/usr/bin/env bash
# Mostra o hardware real da VPS antes de escolher modelos.
set -euo pipefail
echo "== CPU";      nproc; grep -m1 'model name' /proc/cpuinfo || true
echo "== Flags SIMD (AVX2/AVX512 aceleram llama.cpp/Ollama)"; grep -o -m1 -w 'avx2\|avx512f' /proc/cpuinfo | sort -u || echo "sem AVX2"
echo "== Memória";  free -h
echo "== Swap";     swapon --show || true
echo "== Disco";    df -h / | tail -1
echo "== GPU";      (command -v nvidia-smi >/dev/null && nvidia-smi --query-gpu=name,memory.total --format=csv) || echo "nenhuma GPU NVIDIA"
echo
RAM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
echo "== Recomendação inicial para ${RAM_GB} GB (confirme com scripts/benchmark_models.py)"
if   [ "$RAM_GB" -lt 6 ];  then echo "Modelos de 1-2B quantizados (Q4). Sem modelo de visão residente."
elif [ "$RAM_GB" -lt 12 ]; then echo "Um modelo de 3-4B (Q4, ~2.5-3.5 GB) por vez + embedding pequeno. OLLAMA_MAX_LOADED_MODELS=1."
else                            echo "Modelos de 7-8B (Q4) ou 4B + visão em paralelo."
fi
