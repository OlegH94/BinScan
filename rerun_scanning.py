"""
rerun_scanning.py
--------------------------------------------------------------------
Rilancia SOLO vuln_scanner (YARA+taint, semgrep, cwe_checker) ->
fuzz_seed_generator -> reporting, su tutti i binari gia' decompilati
in risultati/ — senza rifare Ghidra o la costruzione del CFG (che
restano quelli gia' su disco, non cambiano quando si aggiornano solo
le regole del vuln_scanner).

Riusa DIRETTAMENTE le stesse funzioni di pipe.py (_phase_vuln_scanner,
_phase_fuzzing, _phase_reporting) — nessuna logica duplicata: se
pipe.py cambia in futuro, questo script segue automaticamente.

Utile dopo aver modificato/aggiunto regole in vuln_scanner/scanner.py
(o le regole semgrep): ci vogliono secondi per binario invece dei
20-30s dell'intera pipeline (quella spesa quasi tutta in Ghidra).

Uso (nessun argomento, gira dalla root del progetto):
    python rerun_scanning.py                    # tutti i binari trovati in risultati/
    python rerun_scanning.py --only NOME_BIN     # solo un binario
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipe import (
    RISULTATI_DIR,
    get_binary_paths,
    _phase_vuln_scanner,
    _phase_fuzzing,
    _phase_reporting,
    _import_ground_truth_if_available,
)
from reporting.aggregate_report import generate_aggregate_report


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _discover_processed_binaries(risultati_dir: Path) -> list[str]:
    """
    A differenza di pipe.discover_binaries() (che guarda bins/), qui
    guardiamo cosa e' gia' stato processato in risultati/ — piu'
    robusto se bins/ e' cambiato nel frattempo (es. avete aggiunto
    nuovi binari selezionati ma non li avete ancora fatti girare):
    questo script si occupa solo di RI-scansionare quello che esiste
    gia', non di processare binari nuovi da zero.
    """
    return sorted(
        d.name for d in risultati_dir.iterdir()
        if d.is_dir() and (d / "decompiled_files").exists()
    )


def rerun_one(binary_name: str, risultati_dir: Path = RISULTATI_DIR) -> dict:
    paths = get_binary_paths(binary_name, risultati_dir)

    decompiled_c = paths.decompiled_dir / f"{binary_name}_decompiled.c"
    symbols_json = paths.decompiled_dir / f"{binary_name}_symbols.json"

    if not decompiled_c.exists():
        print(f"[!] {binary_name}: nessuno pseudocodice decompilato trovato, salto")
        return {"binary": binary_name, "ok": False}

    if not symbols_json.exists():
        symbols_json = None

    target_path = paths.bin_path if paths.bin_path.exists() else None

    print(f"\n{'=' * 70}\n[*] {binary_name}\n{'=' * 70}")

    engine_results = _phase_vuln_scanner(decompiled_c, symbols_json, target_path, paths)
    _phase_fuzzing(decompiled_c, paths)

    timing = _load_json(paths.root / "timing.json", None)
    _phase_reporting(binary_name, paths, timing)

    return {
        "binary": binary_name,
        "ok": True,
        "vuln_findings": {engine: len(f) for engine, f in engine_results.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Rilancia solo vuln_scanner+fuzzing+reporting, senza Ghidra/CFG")
    parser.add_argument("--only", metavar="NOME_BIN", default=None, help="Rilancia solo questo binario")
    parser.add_argument("--from-file", metavar="PATH", default=None,
                         help="Rilancia solo i binari elencati in questo file (un nome per riga, "
                              "es. l'output di find_unresolved_cwe_checker.py)")
    parser.add_argument("--risultati-dir", default=str(RISULTATI_DIR), help="Cartella risultati/ (default: risultati)")
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)

    _import_ground_truth_if_available()

    if args.only:
        binary_names = [args.only]
    elif args.from_file:
        binary_names = [
            line.strip() for line in Path(args.from_file).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        print(f"[*] {len(binary_names)} binari da rilanciare, letti da {args.from_file}")
    else:
        binary_names = _discover_processed_binaries(risultati_dir)
        print(f"[*] {len(binary_names)} binari gia' decompilati trovati in {risultati_dir}")

    results = []
    for binary_name in binary_names:
        results.append(rerun_one(binary_name, risultati_dir))

    print(f"\n{'=' * 70}\n[*] RIEPILOGO\n{'=' * 70}")
    for r in results:
        status = "OK" if r["ok"] else "SALTATO"
        vuln = r.get("vuln_findings", {})
        findings_str = ", ".join(f"{engine}={n}" for engine, n in vuln.items()) or "-"
        print(f"  {r['binary']:<60} [{status}]  finding: {findings_str}")

    if not args.only:
        try:
            agg_summary = generate_aggregate_report(risultati_dir, Path.cwd(), risultati_dir / "aggregate_report.html")
            print(f"\n[+] Report aggregato aggiornato: {risultati_dir / 'aggregate_report.html'}")
            if agg_summary["zero_finding_categories"]:
                print(f"[!] Categorie ancora interamente a zero: {', '.join(agg_summary['zero_finding_categories'])}")
            if agg_summary["overall_true_positive_rate"] is not None:
                print(f"[*] True positive rate complessivo: {agg_summary['overall_true_positive_rate']:.0%}")
        except Exception as e:
            print(f"[!] Report aggregato non generato: {e}")


if __name__ == "__main__":
    main()