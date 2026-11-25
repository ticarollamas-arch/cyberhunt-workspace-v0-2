"""Sobe o servidor real (uvicorn) em porta local e exercita as rotas via HTTP."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

TOKEN = "k" * 48
ROOT = Path(__file__).resolve().parents[1]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.port = free_port()
        env = {**os.environ, "CHAI_API_TOKEN": TOKEN, "CHAI_PROVIDER": "none", "CHAI_ONLINE_VERIFY": "0",
               "CHAI_DATA_DIR": cls.tmp.name, "PYTHONPATH": str(ROOT)}
        cls.proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "cyberhunt_ai.api.server:create_app",
                                     "--factory", "--host", "127.0.0.1", "--port", str(cls.port),
                                     "--log-level", "warning"], env=env, cwd=cls.tmp.name)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(5)
        cls.tmp.cleanup()

    def req(self, path, method="GET", body=None, token=TOKEN, raw=None, ctype="application/json"):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
                                   headers={"Authorization": f"Bearer {token}", "Content-Type": ctype})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_auth_required(self):
        self.assertEqual(self.req("/health", token="errado")[0], 401)

    def test_health_reports_missing_model_server(self):
        code, b = self.req("/health")
        self.assertEqual(code, 200)
        self.assertFalse(b["model_server"]["ok"])

    def test_chat_without_model_is_503_not_fake(self):
        code, b = self.req("/chat", "POST", {"message": "O que é CWE?"})
        self.assertEqual(code, 503)
        self.assertIn("indisponível", b["error"])

    def test_policy_abstains_even_without_model(self):
        code, b = self.req("/chat", "POST", {"message": "Regras do Chrome VRP?", "mode": "policy"})
        self.assertEqual(code, 200)
        self.assertTrue(b["abstained"])

    def test_memory_crud_and_export(self):
        code, m = self.req("/memory", "POST", {"category": "preferences", "content": "Diagramas primeiro"})
        self.assertEqual(code, 200)
        self.assertEqual(self.req("/memory")[1]["memories"][0]["content"], "Diagramas primeiro")
        self.assertEqual(self.req("/memory", "PUT", {"id": m["id"], "content": "Diagramas e exemplos"})[0], 200)
        self.assertEqual(self.req(f"/memory?id={m['id']}", "DELETE")[0], 200)
        self.assertEqual(self.req("/memory", "POST", {"category": "x", "content": "y"})[0], 400)

    def test_documents_and_verify(self):
        code, d = self.req("/documents?filename=nota.md&kind=doc", "POST",
                           raw="# Nota\n\nCookies HttpOnly impedem leitura por JavaScript.".encode(),
                           ctype="text/markdown")
        self.assertEqual(code, 200)
        self.assertEqual(d["chunks"], 1)
        code, v = self.req("/verify", "POST", {"text": "A CWE-79 trata de cross-site scripting.",
                                                "sources": []})
        self.assertEqual(code, 200)
        self.assertEqual(v["checks"][0]["label"], "VERIFIED")  # catálogo seed local

    def test_progress_requires_evidence(self):
        self.assertEqual(self.req("/learning/progress", "POST",
                                  {"topic": "HTTP", "status": "demonstrated"})[0], 400)

    def test_capabilities(self):
        code, c = self.req("/capabilities")
        self.assertEqual(code, 200)
        self.assertIn("study", c["modes"])
        self.assertIn("VERIFIED", c["labels"])

    def test_stt_reports_unavailable(self):
        code, b = self.req("/stt", "POST", raw=b"RIFF....WAVE", ctype="audio/wav")
        self.assertEqual(code, 422)


if __name__ == "__main__":
    unittest.main()
