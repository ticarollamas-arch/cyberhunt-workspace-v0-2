"""Detecção heurística de prompt injection em dados não confiáveis.

Documentos, páginas e código importado são DADOS. Este detector não é
uma barreira perfeita: ele sinaliza trechos suspeitos para que (1) o
orquestrador os rotule no contexto e (2) a interface avise a usuária.
A defesa principal é estrutural: o modelo não tem ferramentas capazes
de executar comandos, enviar dados ou alterar memória sem confirmação.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("override_en", re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all|earlier)\b.{0,30}\b(instructions?|rules|prompts?)", re.I | re.S)),
    ("override_pt", re.compile(r"\b(ignore|desconsidere|esque[çc]a)\b.{0,40}\b(instru[çc][õo]es|regras|prompt)", re.I | re.S)),
    ("role_hijack", re.compile(r"\b(you are now|from now on you|voc[êe] agora [ée]|a partir de agora voc[êe])\b", re.I)),
    ("system_prompt", re.compile(r"\b(system prompt|prompt do sistema|developer message|mensagem do desenvolvedor)\b", re.I)),
    ("chat_tokens", re.compile(r"<\|(im_start|im_end|system|assistant|user)\|>|\[/?INST\]|<<SYS>>", re.I)),
    ("exfiltration", re.compile(r"\b(send|envie|post|upload|exfiltrat\w*)\b.{0,60}\b(api[_ ]?key|token|password|senha|secret|mem[óo]ria|memory)\b", re.I | re.S)),
    ("shell_pipe", re.compile(r"\b(curl|wget)\b[^\n|]{0,200}\|\s*(ba|z)?sh\b", re.I)),
    ("fake_verdict", re.compile(r"\b(mark|classify|label|marque|classifique)\b.{0,40}\b(as|como)\b.{0,20}\b(verified|confirmed|verificad[oa]|confirmad[oa])\b", re.I | re.S)),
]


@dataclass
class InjectionReport:
    suspicious: bool
    signals: list[str]


def scan(text: str) -> InjectionReport:
    signals = [name for name, rx in PATTERNS if rx.search(text or "")]
    return InjectionReport(bool(signals), signals)
