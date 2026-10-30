"""
run_filter_ablation_readelf.py
--------------------------------------------------------------------
Variante di run_filter_ablation.py scoperata sul solo binario readelf
(case study reale, CVE-2021-20294), per avere gli stessi tre livelli
di filtro (none / basic / refined) gia' usati sull'ablation study
Juliet, cosi' da poter confrontare e poi fare seed generation +
fuzzing in modo coerente con la metodologia usata per il dataset
sintetico.

Non modifica pipe.py, rerun_scanning.py ne' scanner.py: li richiama
cosi' come sono. L'unica differenza rispetto allo script originale
e' che copia SOLO risultati\\readelf (non l'intera cartella
risultati\\ con i 142 binari Juliet), e la ricopia mantenendo
l'annidamento "<ablation_dir>\\readelf\\..." perche' rerun_scanning.py
si aspetta una cartella-contenitore con una sottocartella per
binario.

Uso:
    python run_filter_ablation_readelf.py
    python run_filter_ablation_readelf.py --source risultati\\readelf
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

LEVELS = ["none", "basic", "refined"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        default=r"risultati\readelf",
        help="Cartella con la decompilazione/CFG gia' pronti per readelf "
             r"(default: risultati\readelf)",
    )
    parser.add_argument(
        "--binary-name",
        default="readelf",
        help="Nome della sottocartella-binario da ricreare sotto ogni "
             "cartella di ablation (default: readelf)",
    )
    args = parser.parse_args()

    source = Path(args.source)
    if not source.exists():
        print(f"[!] {source} non trovata — controlla il path con --source.")
        return

    print(f"[*] Ablation study su readelf: {len(LEVELS)} livelli di filtro")
    print(f"[*] Sorgente: {source}\n")

    for level in LEVELS:
        ablation_dir = Path(f"risultati_readelf_ablation_{level}")
        target_binary_dir = ablation_dir / args.binary_name

        print(f"{'=' * 70}\nLIVELLO: {level}\n{'=' * 70}")

        if target_binary_dir.exists():
            print(f"[=] {target_binary_dir} esiste gia', la riuso cosi' com'e' "
                  f"(cancellala a mano se vuoi rigenerarla da capo)")
        else:
            print(f"[*] Copio {source} -> {target_binary_dir} ...")
            ablation_dir.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, target_binary_dir)

        env = os.environ.copy()
        env["VULN_SCANNER_FILTER_LEVEL"] = level

        cmd = [sys.executable, "rerun_scanning.py", "--risultati-dir", str(ablation_dir)]
        print(f"[*] Lancio: {' '.join(cmd)}  (VULN_SCANNER_FILTER_LEVEL={level})\n")
        subprocess.run(cmd, env=env)
        print()

    print(f"{'=' * 70}\n[*] RIEPILOGO\n{'=' * 70}")
    print("Confronta CWE-787 trovato/non trovato su print_dynamic_symbol e i")
    print("falsi positivi per ciascun livello, oppure apri i report:")
    for level in LEVELS:
        print(f"    risultati_readelf_ablation_{level}\\{args.binary_name}\\reporting\\*.html")
    print("\nPoi genera i seed e lancia il fuzzing sul livello scelto (di norma")
    print("'refined', quello con cui e' stato trovato il CVE), con:")
    print("    risultati_readelf_ablation_refined\\readelf\\")


if __name__ == "__main__":
    main()