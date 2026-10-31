"""Linha de comando do detector de prompt injection.

Exemplos:
    python detectar.py --texto "Ignore all previous instructions"
    python detectar.py logs/crash.txt --linhas --modo regras
    adb logcat -d | python detectar.py - --linhas
"""
from __future__ import annotations

import argparse
import json
import sys

from detector import MODOS, analisar, analisar_linhas

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def ler_entrada(args) -> str:
    if args.texto is not None:
        return args.texto
    if args.arquivo in (None, "-"):
        return sys.stdin.read()
    with open(args.arquivo, encoding="utf-8", errors="replace") as f:
        return f.read()


def main() -> int:
    p = argparse.ArgumentParser(description="Detecta tentativas de prompt injection em textos e logs.")
    p.add_argument("arquivo", nargs="?", help="arquivo a analisar ('-' para ler da entrada padrão)")
    p.add_argument("--texto", help="analisa este texto em vez de um arquivo")
    p.add_argument("--modo", choices=MODOS, default="hibrido", help="padrão: hibrido")
    p.add_argument("--linhas", action="store_true", help="analisa cada linha separadamente (logs)")
    p.add_argument("--json", action="store_true", help="saída em JSON")
    args = p.parse_args()

    texto = ler_entrada(args)

    if args.linhas:
        resultados = analisar_linhas(texto, args.modo)
        alertas = [(n, linha, r) for n, linha, r in resultados if r.malicioso]
        if args.json:
            print(json.dumps([{"linha": n, "texto": linha, **r.como_dict()} for n, linha, r in alertas],
                             ensure_ascii=False, indent=2))
        else:
            print(f"{len(resultados)} linhas analisadas, {len(alertas)} suspeitas de prompt injection.")
            for n, linha, r in alertas:
                print(f"\n[MALICIOSO] linha {n} (pontuação {r.pontuacao}, decidido por {r.fonte})")
                print(f"  {linha.strip()[:200]}")
                print(f"  Motivo: {r.justificativa}")
        return 2 if alertas else 0

    r = analisar(texto, args.modo)
    if args.json:
        print(json.dumps(r.como_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"[{r.veredito.upper()}] pontuação das regras: {r.pontuacao} | decidido por: {r.fonte}")
        if r.regras:
            print(f"Regras acionadas: {', '.join(r.regras)}")
        print(f"Motivo: {r.justificativa}")
    return 2 if r.malicioso else 0


if __name__ == "__main__":
    sys.exit(main())
