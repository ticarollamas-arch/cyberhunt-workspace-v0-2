"""Voz, áudio e OCR com binários locais.

- Transcrição: whisper.cpp (`whisper-cli`) ou faster-whisper, se instalado.
- Síntese de voz: Piper.
- OCR: Tesseract.
- Conversão de áudio do navegador (webm/ogg) para WAV 16 kHz: ffmpeg.

Os binários são chamados com lista de argumentos fixa (sem shell) e
arquivos temporários. Nada gerado pelo modelo vira argumento de comando.
Se um componente não estiver instalado, a função levanta
MediaUnavailable — a interface mostra isso, não simula o resultado.
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..config import Settings


class MediaUnavailable(Exception):
    pass


def _which(binary: str) -> str | None:
    if not binary:
        return None
    return shutil.which(binary) or (binary if Path(binary).is_file() else None)


def _run(args: list[str], *, input_bytes: bytes | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input_bytes, capture_output=True, timeout=timeout, check=False)


def capabilities(s: Settings) -> dict:
    return {
        "stt": bool((_which(s.whisper_bin) and s.whisper_model and Path(s.whisper_model).is_file())
                    or importlib.util.find_spec("faster_whisper")),
        "stt_engine": "whisper.cpp" if _which(s.whisper_bin) and s.whisper_model else
                      ("faster-whisper" if importlib.util.find_spec("faster_whisper") else None),
        "tts": bool(_which(s.piper_bin) and s.piper_voice and Path(s.piper_voice).is_file()),
        "ffmpeg": bool(_which(s.ffmpeg_bin)),
        "ocr": bool(_which(s.tesseract_bin)),
        "pdf": importlib.util.find_spec("pypdf") is not None,
    }


def _to_wav16k(s: Settings, data: bytes, workdir: Path) -> Path:
    src = workdir / "input.bin"
    src.write_bytes(data)
    dst = workdir / "audio.wav"
    if data[:4] == b"RIFF" and not _which(s.ffmpeg_bin):
        dst.write_bytes(data)
        return dst
    ff = _which(s.ffmpeg_bin)
    if not ff:
        raise MediaUnavailable("ffmpeg não instalado; necessário para converter o áudio do navegador")
    p = _run([ff, "-nostdin", "-y", "-loglevel", "error", "-i", str(src), "-ar", "16000", "-ac", "1",
              "-c:a", "pcm_s16le", str(dst)], timeout=120)
    if p.returncode != 0:
        raise MediaUnavailable(f"ffmpeg falhou: {p.stderr.decode('utf-8', 'replace')[:300]}")
    return dst


def transcribe(s: Settings, audio: bytes, language: str = "pt") -> dict:
    with tempfile.TemporaryDirectory(prefix="chai-stt-") as tmp:
        work = Path(tmp)
        wav = _to_wav16k(s, audio, work)
        wbin = _which(s.whisper_bin)
        if wbin and s.whisper_model and Path(s.whisper_model).is_file():
            out_base = work / "out"
            p = _run([wbin, "-m", s.whisper_model, "-f", str(wav), "-l", language, "-nt", "-otxt",
                      "-of", str(out_base)], timeout=600)
            if p.returncode != 0:
                raise MediaUnavailable(f"whisper.cpp falhou: {p.stderr.decode('utf-8', 'replace')[:300]}")
            txt = out_base.with_suffix(".txt")
            text = txt.read_text("utf-8").strip() if txt.exists() else p.stdout.decode("utf-8", "replace").strip()
            return {"text": text, "engine": "whisper.cpp", "model": Path(s.whisper_model).name}
        if importlib.util.find_spec("faster_whisper"):
            from faster_whisper import WhisperModel  # type: ignore
            model = WhisperModel("small", device="cpu", compute_type="int8")
            segments, info = model.transcribe(str(wav), language=language)
            return {"text": " ".join(seg.text.strip() for seg in segments), "engine": "faster-whisper",
                    "model": "small"}
    raise MediaUnavailable("Nenhum mecanismo de transcrição local instalado (whisper.cpp ou faster-whisper).")


def synthesize(s: Settings, text: str) -> bytes:
    pbin = _which(s.piper_bin)
    if not (pbin and s.piper_voice and Path(s.piper_voice).is_file()):
        raise MediaUnavailable("Piper ou voz (.onnx) não configurados; resposta falada indisponível.")
    text = text.replace("[INFERÊNCIA]", "inferência:").replace("[HIPÓTESE]", "hipótese:") \
               .replace("[DESCONHECIDO]", "desconhecido:")
    with tempfile.TemporaryDirectory(prefix="chai-tts-") as tmp:
        out = Path(tmp) / "speech.wav"
        p = _run([pbin, "--model", s.piper_voice, "--output_file", str(out)],
                 input_bytes=text[:4000].encode("utf-8"), timeout=180)
        if p.returncode != 0 or not out.exists():
            raise MediaUnavailable(f"Piper falhou: {p.stderr.decode('utf-8', 'replace')[:300]}")
        return out.read_bytes()


def ocr_image(s: Settings, image: bytes, lang: str = "por+eng") -> str:
    tbin = _which(s.tesseract_bin)
    if not tbin:
        raise MediaUnavailable("Tesseract não instalado; OCR indisponível.")
    with tempfile.TemporaryDirectory(prefix="chai-ocr-") as tmp:
        src = Path(tmp) / "img"
        src.write_bytes(image)
        p = _run([tbin, str(src), "stdout", "-l", lang], timeout=120)
        if p.returncode != 0:
            # idioma por não instalado: tenta inglês
            p = _run([tbin, str(src), "stdout", "-l", "eng"], timeout=120)
        if p.returncode != 0:
            raise MediaUnavailable(f"Tesseract falhou: {p.stderr.decode('utf-8', 'replace')[:300]}")
        return p.stdout.decode("utf-8", "replace").strip()
