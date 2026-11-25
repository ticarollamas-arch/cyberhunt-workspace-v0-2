"""Teste de ponta a ponta: navegador real -> dev-server (imita Vercel) -> API Python real -> stub do Ollama.

Uso: python3 tests/e2e/run_e2e.py   (requer playwright e Chrome)
Salva capturas de tela em tests/e2e/screens/.
"""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
SHOTS = Path(__file__).with_name("screens")
SHOTS.mkdir(exist_ok=True)
TOKEN = "e" * 48
PASSWORD = "senha-de-teste-123"


def wait_port(port, t=15):
    import socket
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"porta {port} não abriu")


def main():
    tmp = tempfile.mkdtemp(prefix="chl-e2e-")
    pw_hash = subprocess.check_output(
        ["node", "-e", f"import('./lib/session.js').then(m=>process.stdout.write(m.hashPassword('{PASSWORD}',{{N:1024}})))"],
        cwd=ROOT, text=True)
    procs = []
    try:
        procs.append(subprocess.Popen([sys.executable, str(Path(__file__).with_name("ollama_stub.py")), "11999"]))
        env = {**os.environ, "CHAI_API_TOKEN": TOKEN, "CHAI_PROVIDER": "ollama", "CHAI_OLLAMA_URL": "http://127.0.0.1:11999",
               "CHAI_MODEL_GENERAL": "stub-de-teste", "CHAI_ONLINE_VERIFY": "0", "CHAI_DATA_DIR": tmp,
               "PYTHONPATH": str(ROOT / "vps")}
        procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "cyberhunt_ai.api.server:create_app", "--factory",
                                       "--host", "127.0.0.1", "--port", "8799", "--log-level", "warning"], env=env, cwd=tmp))
        denv = {**os.environ, "VPS_URL": "http://127.0.0.1:8799", "VPS_TOKEN": TOKEN, "PORT": "3311",
                "SESSION_SECRET": "x" * 48, "AUTH_PASSWORD_HASH": pw_hash}
        procs.append(subprocess.Popen(["node", "scripts/dev-server.mjs"], cwd=ROOT, env=denv))
        for p in (11999, 8799, 3311):
            wait_port(p)

        with sync_playwright() as pw:
            browser = pw.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto("http://localhost:3311/")

            # 1. Scanner original preservado
            page.click("#demo"); page.click("#run")
            expect(page.locator("#results")).to_contain_text("CWE-79")

            # 2. Login
            page.click('nav button[data-tab="ai"]')
            expect(page.locator("#ai-login")).to_be_visible()
            page.fill("#ai-password", "errada"); page.click("#ai-login button")
            expect(page.locator("#ai-login-msg")).to_contain_text("senha incorreta")
            page.fill("#ai-password", PASSWORD); page.click("#ai-login button")
            expect(page.locator("#ai-app")).to_be_visible()
            expect(page.locator("#ai-status")).to_contain_text("stub-de-teste")
            expect(page.locator("#ai-status")).to_contain_text("transcrição indisponível")

            # 3. Base de conhecimento: upload real
            page.click('[data-ai-tab="kb"]')
            doc = Path(tmp) / "guia.md"
            doc.write_text("# Guia\n\nPath traversal ocorre quando um caminho fornecido pelo usuário escapa do diretório "
                           "autorizado. A defesa recomendada é normalizar o caminho e verificar se o resultado continua "
                           "dentro da raiz permitida.", "utf-8")
            page.set_input_files("#kb-file-input", str(doc))
            page.click("#kb-file button")
            expect(page.locator("#kb-msg")).to_contain_text("Indexado: 1 trechos")
            expect(page.locator("#kb-list")).to_contain_text("SHA-256")
            page.screenshot(path=str(SHOTS / "02-base-conhecimento.png"), full_page=True)

            # 4. Conversa em Research Mode com verificação frase a frase
            page.click('[data-ai-tab="chat"]')
            page.select_option("#ai-mode", "research")
            page.fill("#ai-input", "O que é path traversal e como me defender?")
            page.click("#ai-send")
            bot = page.locator(".msg.bot").last
            expect(bot).to_contain_text("Fundamentação")
            expect(bot.locator(".vbar")).to_contain_text("Sustentado pela fonte: 2")
            expect(bot.locator(".vbar")).to_contain_text("Inferência: 1")
            expect(bot.locator(".vbar")).to_contain_text("Sem fonte: 1")  # frase do valor 31337 não cita fonte
            expect(bot.locator(".warn").first).to_contain_text("identificadores ou valores sem fonte")
            bot.locator("details", has_text="Verificação frase a frase").locator("summary").click()
            bot.locator("details", has_text="Fontes consultadas").locator("summary").click()
            expect(bot).not_to_contain_text("MEMÓRIA_SUGERIDA")
            expect(bot.locator(".suggest")).to_contain_text("nada foi salvo")
            page.screenshot(path=str(SHOTS / "03-resposta-verificada.png"), full_page=True)
            bot.locator(".suggest button", has_text="Salvar").click()
            expect(bot.locator(".suggest")).to_contain_text("Salvo.")

            # 5. Feedback vira correção na memória
            bot.locator("details.feedback summary").click()
            bot.locator("details.feedback textarea").fill("Não há valor de recompensa na fonte; não citar valores.")
            bot.locator("details.feedback button", has_text="Incorreta").click()
            expect(bot.locator("details.feedback small").last).to_contain_text("Correção registrada")
            page.click('[data-ai-tab="memory"]')
            expect(page.locator("#mem-list")).to_contain_text("corrections")
            page.wait_for_selector("#mem-list textarea")
            values = page.eval_on_selector_all("#mem-list textarea", "els => els.map(e => e.value)")
            assert any("estudou path traversal" in v for v in values), values
            assert any("não citar valores" in v for v in values), values
            page.screenshot(path=str(SHOTS / "04-memoria.png"), full_page=True)

            # 6. Policy Mode sem política na base: abstenção
            page.click('[data-ai-tab="chat"]'); page.click("#ai-new")
            page.select_option("#ai-mode", "policy")
            page.fill("#ai-input", "Qual a recompensa máxima do Chrome VRP?")
            page.click("#ai-send")
            expect(page.locator(".msg.bot").last).to_contain_text("abstenção por falta de fonte")
            expect(page.locator(".msg.bot").last).to_contain_text("O modelo não foi chamado")
            expect(page.locator(".msg.bot").last).not_to_contain_text("Fundamentação")

            # 7. Trilhas exigem evidência
            page.click('[data-ai-tab="tracks"]')
            card = page.locator("#ai-tracks article", has_text="HTTP").first
            card.locator("summary").click()
            card.locator("select").select_option("demonstrated")
            card.locator("button", has_text="Salvar progresso").click()
            expect(card.locator("details small")).to_contain_text("exige evidência")
            page.screenshot(path=str(SHOTS / "05-trilhas.png"), full_page=False)

            # 8. Integração com o scanner
            page.click('nav button[data-tab="scan"]')
            page.click("#results button")
            expect(page.locator("#ai-with-code")).to_be_checked()
            expect(page.locator("#ai-input")).to_have_value(__import__("re").compile("alertas do scanner"))

            # 9. Modelo caído: erro explícito, sem resposta substituta
            procs[0].terminate(); procs[0].wait(5)
            page.select_option("#ai-mode", "study")
            page.fill("#ai-input", "Explique CSRF")
            page.click("#ai-send")
            expect(page.locator(".msg.error").last).to_contain_text("Nenhuma resposta substituta")
            page.screenshot(path=str(SHOTS / "06-modelo-offline.png"), full_page=False)

            # 10. Celular
            m = browser.new_page(viewport={"width": 390, "height": 844})
            m.goto("http://localhost:3311/")
            m.screenshot(path=str(SHOTS / "07-mobile.png"), full_page=False)

            assert not errors, errors
            browser.close()
        print("E2E OK — capturas em", SHOTS)
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
