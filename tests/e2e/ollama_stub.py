"""STUB DE TESTE — não é um modelo.

Imita a API HTTP do Ollama com respostas fixas, apenas para testar de ponta
a ponta a interface e o pipeline de verificação. Nunca use em produção.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

REPLY = ("Path traversal ocorre quando um caminho fornecido pelo usuário escapa do diretório autorizado [S1].\n\n"
         "A defesa recomendada é normalizar o caminho e verificar se o resultado continua dentro da raiz permitida [S1].\n\n"
         "[INFERÊNCIA] Links simbólicos exigem um teste separado.\n\n"
         "A recompensa por esse tipo de falha é de 31337 dólares.\n\n"
         "```python\nos.path.realpath(p).startswith(root)\n```\n\n"
         "MEMÓRIA_SUGERIDA[learning]: estudou path traversal (CWE-22)")


class H(BaseHTTPRequestHandler):
    def _send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._send({"models": [{"name": "stub-de-teste"}]})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/api/show":
            return self._send({"capabilities": ["completion"]})
        self._send({"message": {"role": "assistant", "content": REPLY}, "prompt_eval_count": 10, "eval_count": 20})

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
