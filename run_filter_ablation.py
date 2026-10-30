"""
run_filter_ablation.py
--------------------------------------------------------------------
Esperimento di ablation study (Capitolo 6 di tesi): rilancia
rerun_scanning.py TRE volte, una per ciascun livello di filtro delle
funzioni-stub (vuln_scanner/scanner.py), su tre copie separate dei
risultati gia' decompilati — per misurare quanto ciascun livello di
raffinamento incide davvero su TPR/falsi positivi.

Livelli (vedi vuln_scanner/scanner.py):
  1. none     — nessun filtro: scansiona anche stub PTR_ e duplicati halt_baddata
  2. basic    — solo la lista fissa di nomi noti (comportamento originale)
  3. refined  — lista fissa + controllo strutturale con soglia (comportamento attuale)

NON modifica ne' pipe.py ne' rerun_scanning.py: li richiama cosi'
come sono, tre volte, con una variabile d'ambiente diversa
(VULN_SCANNER_FILTER_LEVEL, letta da scanner.py) e una cartella di
output diversa per ciascun livello — il decompilato originale in
risultati/ non viene mai toccato, ogni livello lavora su una propria
copia.

Uso:
    python run_filter_ablation.py
--------------------------------------------------------------------
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

LEVELS = ["none", "basic", "refined"]
SOURCE_RISULTATI = Path("risultati")


def main() -> None:
    if not SOURCE_RISULTATI.exists():
        print(f"[!] {SOURCE_RISULTATI} non trovata — assicurati di essere nella cartella del progetto "
              f"con la campagna Juliet gia' decompilata (ground_truth.json, risultati/ presenti).")
        return

    print(f"[*] Esperimento di ablation study: {len(LEVELS)} livelli di filtro")
    print(f"[*] Ogni livello lavora su una COPIA separata di {SOURCE_RISULTATI} — "
          f"il decompilato originale non viene mai toccato.\n")

    for level in LEVELS:
        target_dir = Path(f"risultati_ablation_{level}")

        print(f"{'=' * 70}\nLIVELLO: {level}\n{'=' * 70}")

        if target_dir.exists():
            print(f"[=] {target_dir} esiste gia', la riuso cosi' com'e' "
                  f"(cancellala a mano se vuoi rigenerarla da capo)")
        else:
            print(f"[*] Copio {SOURCE_RISULTATI} -> {target_dir} (puo' richiedere qualche minuto)...")
            shutil.copytree(SOURCE_RISULTATI, target_dir)

        env = os.environ.copy()
        env["VULN_SCANNER_FILTER_LEVEL"] = level

        cmd = [sys.executable, "rerun_scanning.py", "--risultati-dir", str(target_dir)]
        print(f"[*] Lancio: {' '.join(cmd)}  (VULN_SCANNER_FILTER_LEVEL={level})\n")
        subprocess.run(cmd, env=env)
        print()

    print(f"{'=' * 70}\n[*] RIEPILOGO\n{'=' * 70}")
    print("Confronta il 'True positive rate complessivo' e le 'Categorie ancora")
    print("interamente a zero' stampati sopra per ciascun livello, oppure apri")
    print("i tre report aggregati:")
    for level in LEVELS:
        print(f"    risultati_ablation_{level}\\aggregate_report.html")


if __name__ == "__main__":
    main()