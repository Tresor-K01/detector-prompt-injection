"""Combina regras e LLM num único veredito.

Modos:
- "regras":  só expressões regulares. Rápido, grátis, offline.
- "llm":     só o LLM.
- "hibrido": se as regras tiverem certeza (pontuação 1.0, ou seja, vários sinais
             fortes), decide na hora sem gastar API; caso contrário, pergunta ao
             LLM, passando as regras acionadas como dica. Se o LLM falhar, cai de
             volta para o veredito das regras e avisa.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable

from .llm import Veredito, classificar_com_llm
from .regras import LIMIAR_REGRAS, pontuar

LIMIAR_ATALHO = 1.0
MODOS = ("regras", "llm", "hibrido")

Classificador = Callable[[str, list[str]], Veredito]


@dataclass
class Resultado:
    veredito: str  # "malicioso" ou "benigno"
    pontuacao: float  # pontuação das regras (0 a 1)
    fonte: str  # quem decidiu: "regras", "llm" ou "regras (LLM indisponível)"
    justificativa: str
    regras: list[str] = field(default_factory=list)

    @property
    def malicioso(self) -> bool:
        return self.veredito == "malicioso"

    def como_dict(self) -> dict:
        return asdict(self)


def _pelas_regras(pontuacao: float, regras, fonte: str = "regras") -> Resultado:
    veredito = "malicioso" if pontuacao >= LIMIAR_REGRAS else "benigno"
    justificativa = "; ".join(r.descricao for r in regras) or "Nenhum padrão conhecido encontrado"
    return Resultado(veredito, pontuacao, fonte, justificativa, [r.nome for r in regras])


def analisar(texto: str, modo: str = "hibrido", classificador: Classificador | None = None) -> Resultado:
    if modo not in MODOS:
        raise ValueError(f"modo inválido: {modo!r} (use {', '.join(MODOS)})")

    pontuacao, regras = pontuar(texto)
    nomes = [r.nome for r in regras]

    if modo == "regras":
        return _pelas_regras(pontuacao, regras)

    if modo == "hibrido" and pontuacao >= LIMIAR_ATALHO:
        return _pelas_regras(pontuacao, regras)

    classificador = classificador or classificar_com_llm
    try:
        v = classificador(texto, nomes)
    except Exception as erro:  # rede, chave ausente, resposta inválida...
        if modo == "llm":
            raise
        resultado = _pelas_regras(pontuacao, regras, fonte="regras (LLM indisponível)")
        resultado.justificativa += f" [LLM indisponível: {type(erro).__name__}: {str(erro)[:80]}]"
        return resultado

    return Resultado(v.veredito, pontuacao, "llm", f"{v.tecnica}: {v.justificativa}", nomes)


def analisar_linhas(texto: str, modo: str = "hibrido",
                    classificador: Classificador | None = None) -> list[tuple[int, str, Resultado]]:
    """Analisa cada linha não vazia separadamente (útil para logs)."""
    return [
        (numero, linha, analisar(linha, modo, classificador))
        for numero, linha in enumerate(texto.splitlines(), start=1)
        if linha.strip()
    ]
