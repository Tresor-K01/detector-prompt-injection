"""Avalia o detector contra um conjunto rotulado e imprime as métricas.

Uso:
    python avaliar.py                      # modo regras (não precisa de chave da API)
    python avaliar.py --modo hibrido       # precisa de ANTHROPIC_API_KEY no .env
    python avaliar.py --modo llm --erros   # mostra cada erro
"""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict

from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from detector import MODOS, analisar

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

POSITIVO = "malicioso"


def carregar(caminho: str) -> list[dict]:
    with open(caminho, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main() -> None:
    p = argparse.ArgumentParser(description="Avalia o detector de prompt injection.")
    p.add_argument("--modo", choices=MODOS, default="regras")
    p.add_argument("--dados", default="dados/exemplos.csv")
    p.add_argument("--erros", action="store_true", help="lista os exemplos classificados errado")
    args = p.parse_args()

    exemplos = carregar(args.dados)
    reais, previstos, fontes, erros = [], [], defaultdict(int), []
    acertos_por_categoria = defaultdict(lambda: [0, 0])

    for ex in exemplos:
        r = analisar(ex["texto"], args.modo)
        reais.append(ex["rotulo"])
        previstos.append(r.veredito)
        fontes[r.fonte] += 1
        cat = acertos_por_categoria[ex["categoria"]]
        cat[1] += 1
        if r.veredito == ex["rotulo"]:
            cat[0] += 1
        else:
            erros.append((ex, r))

    precisao, recall, f1, _ = precision_recall_fscore_support(
        reais, previstos, pos_label=POSITIVO, average="binary", zero_division=0)
    acuracia = sum(a == b for a, b in zip(reais, previstos)) / len(reais)
    (vn, fp), (fn, vp) = confusion_matrix(reais, previstos, labels=["benigno", POSITIVO])

    print(f"Modo: {args.modo} | {len(exemplos)} exemplos ({reais.count(POSITIVO)} maliciosos)\n")
    print(f"Acurácia:  {acuracia:.2f}")
    print(f"Precisão:  {precisao:.2f}   (dos que marquei como maliciosos, quantos eram)")
    print(f"Recall:    {recall:.2f}   (dos maliciosos, quantos eu peguei)")
    print(f"F1:        {f1:.2f}\n")
    print("Matriz de confusão          previsto benigno   previsto malicioso")
    print(f"  real benigno                    {vn:>3}                {fp:>3}")
    print(f"  real malicioso                  {fn:>3}                {vp:>3}\n")

    print("Acertos por categoria:")
    for nome, (ok, total) in sorted(acertos_por_categoria.items()):
        print(f"  {nome:<22} {ok}/{total}")
    print("\nQuem decidiu: " + ", ".join(f"{k}={v}" for k, v in fontes.items()))

    if args.erros and erros:
        print("\nErros:")
        for ex, r in erros:
            tipo = "falso negativo" if ex["rotulo"] == POSITIVO else "falso positivo"
            print(f"- [{tipo}] {ex['texto'][:110]!r}")
            print(f"    regras: {r.regras or '-'} | {r.justificativa[:120]}")


if __name__ == "__main__":
    main()
