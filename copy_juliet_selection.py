r"""
copy_juliet_selection.py
--------------------------------------------------------------------
Modulo unico standalone (non fa parte della pipeline) per popolare
bins/ e sources/ del progetto a partire da selected_bins.txt e dalla
cartella Juliet completa (sorgenti in testcases/CWE121_.../s01..s09,
binari gia' compilati in bin/CWE121/bad).

I path UNC di WSL (\\wsl.localhost\...) sono leggibili direttamente
da Python/pathlib su Windows senza bisogno di copiarli prima in
locale, purche' WSL sia in esecuzione — i default sotto puntano gia'
li'. Se preferite comunque una copia locale per velocita' (evita
l'overhead della condivisione di rete), aggiornate le due costanti
DEFAULT_JULIET_SRC_DIR / DEFAULT_JULIET_BIN_DIR.

Per ogni binario in selected_bins.txt:
  1. copia il binario (cercato per nome esatto, ricorsivamente, utile
     anche se in futuro la struttura bin/CWE121/bad cambiasse) in bins/
  2. deriva il nome base togliendo il suffisso "-bad"/"-good", cerca
     ricorsivamente in testcases/CWE121.../s01..s09 tutti i file
     "<base>.c", "<base>a.c", "<base>b.c" (gestisce da solo sia i
     testcase a file singolo sia quelli a piu' file — stessa
     convenzione a/b gia' usata da juliet_ground_truth_importer.py)
     e li copia in sources/, appiattendo la struttura (l'importer si
     aspetta sources/<nome_file>, non un percorso annidato per sXX).

Uso (con i default gia' impostati sui vostri path):
    python copy_juliet_selection.py

Uso con path diversi:
    python copy_juliet_selection.py \
        --selection selected_bins.txt \
        --juliet-bin-dir "\\wsl.localhost\kali-linux\home\kali\juliet-test-suite-c\bin\CWE121\bad" \
        --juliet-src-dir "\\wsl.localhost\kali-linux\home\kali\juliet-test-suite-c\testcases\CWE121_Stack_Based_Buffer_Overflow" \
        --bins-out bins \
        --sources-out sources
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

DEFAULT_SELECTION_FILE = Path("selected_bins.txt")
DEFAULT_JULIET_BIN_DIR = Path(r"<JULIET_DIR>\bad")
DEFAULT_JULIET_SRC_DIR = Path(r"<JULIET_DIR>\sources")
# Puntano DIRETTAMENTE alle cartelle del progetto (non alla cartella di
# staging "...\vulns\binari selezionati\bins"): risparmia un passaggio
# di copia manuale in piu'. Se preferite tenerle separate, sovrascrivete
# con --bins-out / --sources-out da riga di comando.
DEFAULT_BINS_OUT = Path("bins")
DEFAULT_SOURCES_OUT = Path("sources")


def _strip_variant_suffix(binary_name: str) -> str:
    for suffix in ("-bad", "-good"):
        if binary_name.endswith(suffix):
            return binary_name[: -len(suffix)]
    return binary_name


def _index_files_by_name(root: Path, pattern: str, label: str) -> dict:
    """
    Scansiona root UNA SOLA VOLTA (invece di una rglob() per ogni
    binario/sorgente cercato) e ritorna {nome_file: Path}. Necessario
    perche' rglob() riparte da zero a ogni chiamata: farne una per
    ciascuno dei 142 binari, moltiplicata per le lettere di variante
    a/b/c... da controllare, significava centinaia di scansioni
    complete dell'albero — su un path di rete WSL (\\wsl.localhost,
    protocollo 9P) diventa lentissimo e sembra "bloccato" anche se
    sta solo lavorando (bug di performance scoperto durante l'uso
    reale, corretto qui).
    """
    print(f"[*] Indicizzazione {label} in {root} (una scansione unica, puo' richiedere qualche minuto su path di rete)...")
    index: dict[str, Path] = {}
    count = 0
    for p in root.rglob(pattern):
        if p.is_file():
            index[p.name] = p
            count += 1
            if count % 500 == 0:
                print(f"    ... {count} file indicizzati finora")
    print(f"[+] {count} file trovati in totale.")
    return index


def copy_selection(
    selection_file: Path,
    juliet_bin_dir: Path,
    juliet_src_dir: Path,
    bins_out: Path,
    sources_out: Path,
) -> None:
    bins_out.mkdir(parents=True, exist_ok=True)
    sources_out.mkdir(parents=True, exist_ok=True)

    binary_names = [
        line.strip() for line in selection_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    print(f"[*] {len(binary_names)} binari da cercare/copiare")

    bin_index = _index_files_by_name(juliet_bin_dir, "*", "binari")
    src_index = _index_files_by_name(juliet_src_dir, "*.c", "sorgenti .c")

    bins_copied = bins_missing = sources_copied = sources_missing = 0

    for i, binary_name in enumerate(binary_names, 1):
        if i % 20 == 0 or i == len(binary_names):
            print(f"[*] Elaborati {i}/{len(binary_names)}...")

        # --- binario: lookup diretto nell'indice, niente rglob ---
        found_bin = bin_index.get(binary_name)
        if found_bin:
            shutil.copy2(found_bin, bins_out / binary_name)
            bins_copied += 1
        else:
            print(f"[!] Binario non trovato: {binary_name}")
            bins_missing += 1

        # --- sorgenti: stesso lookup diretto, per ogni possibile variante a/b/c... ---
        base_name = _strip_variant_suffix(binary_name)
        candidates = [f"{base_name}.c"] + [f"{base_name}{letter}.c" for letter in "abcdefgh"]

        found_any = False
        for candidate_name in candidates:
            src_path = src_index.get(candidate_name)
            if src_path is None:
                continue
            found_any = True
            dest = sources_out / candidate_name
            if dest.exists():
                continue
            shutil.copy2(src_path, dest)
            sources_copied += 1

        if not found_any:
            print(f"[!] Nessun sorgente trovato per: {base_name}")
            sources_missing += 1

    print()
    print(f"[+] Binari: {bins_copied} copiati, {bins_missing} non trovati")
    print(f"[+] Sorgenti: {sources_copied} file copiati, {sources_missing} testcase senza sorgente trovato")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Copia i binari Juliet selezionati e i relativi sorgenti")
    parser.add_argument("--selection", default=str(DEFAULT_SELECTION_FILE), help="File con un nome binario per riga (default: selected_bins.txt)")
    parser.add_argument("--juliet-bin-dir", default=str(DEFAULT_JULIET_BIN_DIR), help="Cartella con i binari Juliet gia' compilati")
    parser.add_argument("--juliet-src-dir", default=str(DEFAULT_JULIET_SRC_DIR), help="Cartella con i sorgenti .c Juliet (contiene s01..s09)")
    parser.add_argument("--bins-out", default=str(DEFAULT_BINS_OUT), help="Cartella di destinazione per i binari (default: bins)")
    parser.add_argument("--sources-out", default=str(DEFAULT_SOURCES_OUT), help="Cartella di destinazione per i sorgenti (default: sources)")
    args = parser.parse_args()

    copy_selection(
        Path(args.selection),
        Path(args.juliet_bin_dir),
        Path(args.juliet_src_dir),
        Path(args.bins_out),
        Path(args.sources_out),
    )