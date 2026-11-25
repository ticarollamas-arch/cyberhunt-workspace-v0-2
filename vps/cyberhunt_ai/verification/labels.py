"""Classificações epistêmicas usadas em toda a plataforma."""
from __future__ import annotations

from enum import Enum


class Label(str, Enum):
    VERIFIED = "VERIFIED"                    # conferido em fonte autoritativa por verificador independente
    SOURCE_SUPPORTED = "SOURCE_SUPPORTED"    # sustentado por trecho citado da base de conhecimento
    INFERRED = "INFERRED"                    # interpretação declarada pelo modelo
    HYPOTHESIS = "HYPOTHESIS"                # hipótese declarada, precisa de teste
    UNVERIFIED = "UNVERIFIED"                # afirmação sem fonte
    OUTDATED = "OUTDATED"                    # fonte existe, mas está velha demais para a finalidade
    CONTRADICTED = "CONTRADICTED"            # verificador encontrou evidência contrária
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # cita fonte, mas o trecho não sustenta


# Ordem de gravidade usada para resumir uma resposta inteira.
SEVERITY = {
    Label.CONTRADICTED: 6,
    Label.UNVERIFIED: 5,
    Label.INSUFFICIENT_EVIDENCE: 4,
    Label.OUTDATED: 3,
    Label.HYPOTHESIS: 2,
    Label.INFERRED: 1,
    Label.SOURCE_SUPPORTED: 0,
    Label.VERIFIED: 0,
}

DESCRIPTIONS_PT = {
    Label.VERIFIED: "Conferido em fonte autoritativa por verificação independente do modelo.",
    Label.SOURCE_SUPPORTED: "Sustentado por trecho citado de documento da base.",
    Label.INFERRED: "Interpretação declarada; não é fato documentado.",
    Label.HYPOTHESIS: "Hipótese técnica; exige teste ou evidência.",
    Label.UNVERIFIED: "Afirmação sem fonte. Não use como fato.",
    Label.OUTDATED: "A fonte pode estar desatualizada; confirme a versão vigente.",
    Label.CONTRADICTED: "O verificador encontrou evidência contrária.",
    Label.INSUFFICIENT_EVIDENCE: "A fonte citada não sustenta a afirmação.",
}
