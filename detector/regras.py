"""Regras heurísticas (expressões regulares) para detectar prompt injection.

As regras são rápidas, gratuitas e explicáveis, mas só reconhecem padrões
conhecidos. Por isso o modo híbrido usa um LLM para os casos que as regras
não conseguem decidir sozinhas.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Limiar a partir do qual o modo "regras" considera o texto malicioso.
LIMIAR_REGRAS = 0.6

# Caracteres invisíveis usados para quebrar palavras e enganar filtros
# (zero-width space, joiners, marcas de direção de texto, BOM).
INVISIVEIS = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")


@dataclass(frozen=True)
class Regra:
    nome: str
    peso: float
    padrao: re.Pattern
    descricao: str


def _re(padrao: str) -> re.Pattern:
    return re.compile(padrao, re.IGNORECASE | re.MULTILINE)


REGRAS: list[Regra] = [
    Regra(
        "ignorar_instrucoes",
        0.7,
        _re(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions?|rules|prompts?|directives)\b"),
        "Pede para ignorar instruções ou regras (inglês)",
    ),
    Regra(
        "ignorar_instrucoes_pt",
        0.7,
        _re(r"\b(ignore|ignora|ignorar|esqueca|esquecer|desconsidere|desconsiderar|despreze)\b"
            r".{0,40}\b(instrucoes|instrucao|regras|ordens|diretrizes|prompt)\b"),
        "Pede para ignorar instruções ou regras (português)",
    ),
    Regra(
        "novo_papel",
        0.5,
        _re(r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|"
            r"voce agora e|a partir de agora,? voce|finja (ser|que)|aja como)\b"),
        "Tenta fazer o modelo assumir outro papel",
    ),
    Regra(
        "extrair_prompt",
        0.6,
        _re(r"\b(reveal|show|print|repeat|leak|output)\b.{0,25}"
            r"\b(system prompt|your (instructions|prompt)|hidden instructions)\b"
            r"|\b(mostre|revele|repita|imprima|vaze)\b.{0,25}"
            r"\b(prompt|instrucoes (do sistema|ocultas|internas))\b"),
        "Tenta extrair o prompt do sistema",
    ),
    Regra(
        "marcador_de_papel",
        0.5,
        _re(r"(^\s*(system|assistant|sistema|assistente)\s*:)"
            r"|(<\|im_start\|>|<\|im_end\|>|\[/?inst\]|</?system>|###\s*(system|instruction|instrucao))"),
        "Imita marcadores de conversa (system:, [INST], <|im_start|>)",
    ),
    Regra(
        "modo_irrestrito",
        0.6,
        _re(r"\b(developer mode|dan mode|jailbreak|no restrictions|without (any )?restrictions|"
            r"modo desenvolvedor|sem (nenhuma )?restric(ao|oes)|sem filtros?)\b"),
        "Pede um modo sem restrições (jailbreak)",
    ),
    Regra(
        "ordem_ao_classificador",
        0.5,
        _re(r"\b(classify|mark|label|report|classifique|marque|rotule|considere)\b.{0,40}"
            r"\b(as|como)\b.{0,15}\b(low|safe|benign|harmless|baixa|segur[oa]|benign[oa]|inofensiv[oa])\b"),
        "Tenta forçar o resultado de uma classificação",
    ),
    Regra(
        "exfiltracao",
        0.6,
        _re(r"\b(send|post|upload|forward|envie|mande|encaminhe)\b.{0,60}\bhttps?://"
            r"|!\[[^\]]*\]\(https?://[^)]*\?[^)]*="),
        "Tenta enviar dados para uma URL externa",
    ),
    Regra(
        "bloco_base64",
        0.2,
        re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
        "Bloco longo em base64 (possível payload escondido)",
    ),
]

# Frases conhecidas procuradas no texto sem espaços nem pontuação, para pegar
# ofuscações como "i g n o r e  p r e v i o u s".
FRASES_COMPACTAS = (
    "ignorepreviousinstructions",
    "ignoreallpreviousinstructions",
    "ignoreallinstructions",
    "disregardpreviousinstructions",
    "revealyoursystemprompt",
    "ignoreasinstrucoes",
    "ignoretodasasinstrucoes",
    "esquecatodasasinstrucoes",
)

REGRA_INVISIVEIS = Regra("caracteres_invisiveis", 0.3, INVISIVEIS, "Contém caracteres invisíveis")
REGRA_OFUSCACAO = Regra("ofuscacao_espacos", 0.7, re.compile(""), "Frase de ataque escondida com espaços ou símbolos")


def normalizar(texto: str) -> str:
    """Remove invisíveis, acentos e variantes de largura (ex.: ＩＧＮＯＲＥ) e põe em minúsculas."""
    texto = INVISIVEIS.sub("", texto)
    texto = unicodedata.normalize("NFKD", texto)
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    return texto.lower()


def pontuar(texto: str) -> tuple[float, list[Regra]]:
    """Devolve a pontuação (0 a 1) e a lista de regras acionadas."""
    acionadas: list[Regra] = []

    if INVISIVEIS.search(texto):
        acionadas.append(REGRA_INVISIVEIS)

    normal = normalizar(texto)
    for regra in REGRAS:
        if regra.padrao.search(normal):
            acionadas.append(regra)

    ja_pegou_ignorar = any(r.nome.startswith("ignorar") for r in acionadas)
    compacto = re.sub(r"[^a-z]", "", normal)
    if not ja_pegou_ignorar and any(f in compacto for f in FRASES_COMPACTAS):
        acionadas.append(REGRA_OFUSCACAO)

    pontuacao = min(1.0, sum(r.peso for r in acionadas))
    return round(pontuacao, 2), acionadas
