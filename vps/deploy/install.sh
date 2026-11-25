#!/usr/bin/env bash
# Instalação na VPS (Ubuntu/Debian). Leia antes de executar. Rode como root.
set -euo pipefail

APP=/opt/cyberhunt-ai
DATA=/var/lib/cyberhunt-ai

apt-get update
apt-get install -y python3-venv python3-pip ffmpeg tesseract-ocr tesseract-ocr-por caddy curl

id cyberhunt >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin cyberhunt
mkdir -p "$APP" "$DATA"
cp -r "$(dirname "$0")/.." "$APP/vps"
cp -r "$(dirname "$0")/../../knowledge" "$APP/knowledge"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -r "$APP/vps/requirements.txt"
chown -R cyberhunt:cyberhunt "$DATA"

# Ollama (script oficial). Revise https://ollama.com/download antes de rodar.
if ! command -v ollama >/dev/null; then
  curl -fsSL https://ollama.com/install.sh -o /tmp/ollama-install.sh
  less /tmp/ollama-install.sh   # leia o script
  sh /tmp/ollama-install.sh
fi
mkdir -p /etc/systemd/system/ollama.service.d
cp "$APP/vps/deploy/ollama-override.conf" /etc/systemd/system/ollama.service.d/override.conf

if [ ! -f /etc/cyberhunt-ai.env ]; then
  cp "$APP/vps/.env.example" /etc/cyberhunt-ai.env
  TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
  sed -i "s|^CHAI_API_TOKEN=.*|CHAI_API_TOKEN=$TOKEN|" /etc/cyberhunt-ai.env
  chmod 600 /etc/cyberhunt-ai.env
  echo "Token gerado em /etc/cyberhunt-ai.env — copie para VPS_TOKEN no Vercel."
fi

# Wrapper para rodar scripts com o ambiente do serviço, como usuário sem privilégios.
cat > /usr/local/bin/chai-run <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/cyberhunt-ai/vps
exec sudo -u cyberhunt bash -c 'set -a; . /etc/cyberhunt-ai.env; set +a; exec /opt/cyberhunt-ai/venv/bin/python "$@"' _ "$@"
WRAP
chmod 755 /usr/local/bin/chai-run

cp "$APP/vps/deploy/cyberhunt-ai.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ollama cyberhunt-ai

echo
echo "Próximos passos:"
echo " 1. bash $APP/vps/scripts/check_hardware.sh"
echo " 2. ollama pull <modelo candidato>   (ex.: qwen3:4b, gemma3:4b)"
echo " 3. chai-run -m scripts.benchmark_models <modelo1> <modelo2>"
echo " 4. Ajuste CHAI_MODEL_* em /etc/cyberhunt-ai.env e: systemctl restart cyberhunt-ai"
echo " 5. chai-run -m scripts.ingest_sources ../knowledge/sources.json"
echo "    chai-run -m cyberhunt_ai.evaluations.runner     (avaliação anti-alucinação do modelo escolhido)"
echo " 6. Configure o DNS do subdomínio e copie deploy/Caddyfile para /etc/caddy/Caddyfile; systemctl reload caddy"
