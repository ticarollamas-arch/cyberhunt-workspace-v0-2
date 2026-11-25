"""API HTTP privada da Cyber Hunt AI (Starlette + Uvicorn).

Executar na VPS:
    CHAI_API_TOKEN=... uvicorn cyberhunt_ai.api.server:app --host 127.0.0.1 --port 8765

Exponha à internet apenas via proxy reverso com TLS (veja deploy/Caddyfile).
Toda rota exige "Authorization: Bearer <CHAI_API_TOKEN>". Quem chama é a
função serverless do Vercel, que guarda o token no backend; o navegador
nunca vê o token.
"""
from __future__ import annotations

import hmac
import json
import logging

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .. import __version__
from ..config import Settings
from ..core.model_router import CapabilityMissing
from ..core.orchestrator import ChatRequest, Orchestrator
from ..db import Database
from ..multimodal import local_media
from ..providers import ProviderUnavailable, build_provider
from ..specialists.prompts import MODES, PROMPT_VERSION
from ..verification.labels import DESCRIPTIONS_PT

log = logging.getLogger("cyberhunt_ai")


def create_app(settings: Settings | None = None, provider=None, verifier=None) -> Starlette:
    s = settings or Settings()
    if not s.api_token or len(s.api_token) < 32:
        raise RuntimeError("Defina CHAI_API_TOKEN com pelo menos 32 caracteres aleatórios.")
    s.ensure_dirs()
    provider = provider or build_provider(s)
    orch = Orchestrator(s, provider, db=Database(s.db_path), verifier=verifier)

    class Auth(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            header = request.headers.get("authorization", "")
            token = header[7:] if header.lower().startswith("bearer ") else ""
            if not hmac.compare_digest(token.encode(), s.api_token.encode()):
                return JSONResponse({"error": "não autorizado"}, status_code=401)
            length = int(request.headers.get("content-length") or 0)
            if length > s.max_upload_bytes:
                return JSONResponse({"error": "corpo grande demais"}, status_code=413)
            return await call_next(request)

    async def body_json(request: Request) -> dict:
        raw = await request.body()
        if len(raw) > s.max_upload_bytes:
            raise ValueError("corpo grande demais")
        return json.loads(raw or b"{}")

    def err(msg: str, code: int = 400) -> JSONResponse:
        return JSONResponse({"error": msg}, status_code=code)

    # --- rotas -----------------------------------------------------------
    async def health(request: Request):
        return JSONResponse({"ok": True, "version": __version__, "prompt_version": PROMPT_VERSION,
                             "model_server": provider.health()})

    async def capabilities(request: Request):
        vision = False
        if s.model_vision:
            caps = orch.router.caps(s.model_vision)
            vision = "vision" in caps
        return JSONResponse({
            "models": {"general": s.model_general, "code": s.model_code or s.model_general,
                       "vision": s.model_vision or None, "embed": s.model_embed or None},
            "vision": vision, "embeddings": bool(s.model_embed),
            "media": local_media.capabilities(s),
            "online_verification": s.online_verification,
            "cwe_catalog_complete": orch.verifier.catalog.is_complete(),
            "modes": {k: v["label"] for k, v in MODES.items()},
            "labels": {k.value: v for k, v in DESCRIPTIONS_PT.items()},
        })

    async def chat(request: Request):
        try:
            b = await body_json(request)
            msg = str(b.get("message", "")).strip()
            if not msg:
                return err("mensagem vazia")
            req = ChatRequest(message=msg[:20000], mode=str(b.get("mode", "study")),
                              conversation_id=b.get("conversation_id"),
                              parent_conversation_id=b.get("parent_conversation_id"),
                              code=str(b.get("code", ""))[:300000], code_origin=str(b.get("code_origin", ""))[:500],
                              scanner_findings=list(b.get("scanner_findings") or [])[:200],
                              images=[str(i) for i in (b.get("images") or [])][:4],
                              collections=b.get("collections") or None)
            return JSONResponse(orch.chat(req))
        except CapabilityMissing as exc:
            return err(str(exc), 422)
        except ProviderUnavailable as exc:
            return err(f"Modelo local indisponível: {exc}", 503)
        except (ValueError, TypeError) as exc:
            return err(str(exc))

    async def verify(request: Request):
        b = await body_json(request)
        return JSONResponse(orch.verify_text(str(b.get("text", ""))[:50000], b.get("sources") or []))

    async def conversations(request: Request):
        if request.method == "GET":
            cid = request.query_params.get("id")
            if cid:
                return JSONResponse({"conversation": orch.conversations.get(int(cid)),
                                     "messages": orch.conversations.messages(int(cid))})
            return JSONResponse({"conversations": orch.conversations.list()})
        if request.method == "DELETE":
            orch.conversations.delete(int(request.query_params["id"]))
            return JSONResponse({"ok": True})
        return err("método não suportado", 405)

    async def memory(request: Request):
        try:
            if request.method == "GET":
                if request.query_params.get("export"):
                    return Response(orch.memory.export_json(), media_type="application/json",
                                    headers={"Content-Disposition": "attachment; filename=cyberhunt-memoria.json"})
                return JSONResponse({"memories": orch.memory.list(request.query_params.get("category"))})
            b = await body_json(request) if request.method in ("POST", "PUT") else {}
            if request.method == "POST":
                return JSONResponse(orch.memory.add(b.get("category", ""), b.get("content", ""),
                                                    origin=b.get("origin", "user")))
            if request.method == "PUT":
                return JSONResponse(orch.memory.update(int(b["id"]), b.get("content", "")))
            if request.method == "DELETE":
                orch.memory.delete(int(request.query_params["id"]))
                return JSONResponse({"ok": True})
        except (ValueError, KeyError) as exc:
            return err(str(exc))
        return err("método não suportado", 405)

    async def progress(request: Request):
        try:
            if request.method == "GET":
                return JSONResponse({"progress": orch.memory.progress()})
            b = await body_json(request)
            return JSONResponse(orch.memory.set_progress(b.get("topic", ""), b.get("status", ""),
                                                         b.get("evidence", "")))
        except ValueError as exc:
            return err(str(exc))

    async def feedback(request: Request):
        try:
            b = await body_json(request)
            return JSONResponse(orch.record_feedback(int(b["message_id"]), str(b.get("rating", "")),
                                                     str(b.get("correction", "")), str(b.get("reference_url", ""))))
        except (ValueError, KeyError) as exc:
            return err(str(exc))

    async def documents(request: Request):
        try:
            if request.method == "GET":
                return JSONResponse({"documents": orch.ingestor.list()})
            if request.method == "DELETE":
                orch.ingestor.delete(int(request.query_params["id"]))
                return JSONResponse({"ok": True})
            ctype = request.headers.get("content-type", "")
            if ctype.startswith("application/json"):
                b = await body_json(request)
                if b.get("url"):
                    return JSONResponse(orch.ingestor.add_url(b["url"], kind=b.get("kind", "doc"),
                                                              collection=b.get("collection", "general"),
                                                              license=b.get("license", "")))
                return JSONResponse(orch.ingestor.add_text(title=b.get("title", "Texto colado"),
                                                           text=b.get("text", ""), kind=b.get("kind", "doc"),
                                                           collection=b.get("collection", "private")))
            data = await request.body()
            name = request.query_params.get("filename", "upload.txt")
            kind = request.query_params.get("kind", "doc")
            if name.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                text = local_media.ocr_image(s, data)
                return JSONResponse(orch.ingestor.add_text(title=name + " (OCR)", text=text, kind=kind,
                                                           collection="private", provenance="user_upload"))
            return JSONResponse(orch.ingestor.add_file(name, data, kind=kind,
                                                       collection=request.query_params.get("collection", "private")))
        except local_media.MediaUnavailable as exc:
            return err(str(exc), 422)
        except (ValueError, KeyError) as exc:
            return err(str(exc))

    async def stt(request: Request):
        try:
            data = await request.body()
            if not data:
                return err("áudio vazio")
            return JSONResponse(local_media.transcribe(s, data, request.query_params.get("lang", "pt")))
        except local_media.MediaUnavailable as exc:
            return err(str(exc), 422)

    async def tts(request: Request):
        try:
            b = await body_json(request)
            wav = local_media.synthesize(s, str(b.get("text", "")))
            return Response(wav, media_type="audio/wav")
        except local_media.MediaUnavailable as exc:
            return err(str(exc), 422)

    async def ocr(request: Request):
        try:
            return JSONResponse({"text": local_media.ocr_image(s, await request.body())})
        except local_media.MediaUnavailable as exc:
            return err(str(exc), 422)

    routes = [
        Route("/health", health),
        Route("/capabilities", capabilities),
        Route("/chat", chat, methods=["POST"]),
        Route("/verify", verify, methods=["POST"]),
        Route("/conversations", conversations, methods=["GET", "DELETE"]),
        Route("/memory", memory, methods=["GET", "POST", "PUT", "DELETE"]),
        Route("/learning/progress", progress, methods=["GET", "POST"]),
        Route("/feedback", feedback, methods=["POST"]),
        Route("/documents", documents, methods=["GET", "POST", "DELETE"]),
        Route("/stt", stt, methods=["POST"]),
        Route("/tts", tts, methods=["POST"]),
        Route("/ocr", ocr, methods=["POST"]),
    ]
    app = Starlette(routes=routes, middleware=[Middleware(Auth)])
    app.state.orchestrator = orch
    return app


# Executar com: uvicorn cyberhunt_ai.api.server:create_app --factory --host 127.0.0.1 --port 8765
