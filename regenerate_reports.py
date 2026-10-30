"""
regenerate_reports.py
--------------------------------------------------------------------
Rigenera report.html + report.sarif per TUTTI i binari gia' presenti
in risultati/ (o nella cartella indicata con --risultati-dir), usando
i dati gia' scritti su disco (findings_all.json, timing.json,
manifest.json del fuzzer) — senza rilanciare Ghidra, angr o i tre
motori del vuln_scanner.

Utile quando i dati grezzi sono gia' corretti ma la generazione del
report vero e proprio era rotta (es. template Jinja2 vuoto/corrotto
su disco), o quando serve solo aggiornare la sezione codice
decompilato/sorgente senza rifare la scansione: ci vogliono pochi
secondi invece di rifare un batch intero da capo.

Genera anche <risultati-dir>/aggregate_report.html a fine giro.

`sources/` e `ground_truth.json` restano SEMPRE nella root del
progetto (condivisi tra le eventuali cartelle di ablation study,
vedi run_filter_ablation.py — quello script copia solo risultati/,
non sources/ ne' ground_truth.json, quindi vanno risolti sempre li'
indipendentemente da quale <risultati-dir> si sta rigenerando).

Uso:
    python regenerate_reports.py
    python regenerate_reports.py --risultati-dir risultati_ablation_refined
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reporting.report_generator import generate_report
from reporting.aggregate_report import generate_aggregate_report
from reporting.juliet_ground_truth_importer import resolve_source_paths

PROJECT_ROOT = Path(".")
SOURCES_DIR = Path("sources")
JULIET_MANIFEST_PATH = SOURCES_DIR / "manifest.xml"


def _find_decompiled_c(binary_dir: Path) -> Path | None:
    """
    Cerca il file .c con lo pseudocodice decompilato dentro
    <binary_dir>/decompiled_files/ (il nome della cartella e' fisso,
    scritto da DecompScript.java - vedi pipe.py:BinaryPaths). Il nome
    del FILE dentro quella cartella non e' invece fissato qui, quindi
    lo cerchiamo con un glob invece di assumerlo.

    Ritorna None (nessuna eccezione) se la cartella non esiste, e'
    vuota, o ne contiene piu' di uno (caso ambiguo: meglio segnalarlo
    e degradare a "nessun decompilato" che indovinare quale usare).
    """
    decompiled_dir = binary_dir / "decompiled_files"
    if not decompiled_dir.is_dir():
        return None

    c_files = sorted(decompiled_dir.glob("*.c"))
    if not c_files:
        return None
    if len(c_files) > 1:
        print(f"[!] {decompiled_dir}: trovati {len(c_files)} file .c, "
              f"uso il primo ({c_files[0].name}) - verificare se e' un caso atteso")
    return c_files[0]


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"[!] {path} non e' JSON valido, ignorato")
        return default


def main() -> None:
    parser = argparse.ArgumentParser(description="Rigenera report.html + report.sarif senza rifare la scansione")
    parser.add_argument("--risultati-dir", default="risultati",
                         help="Cartella risultati/ da rigenerare (default: risultati). "
                              "Usala per puntare a una cartella di ablation study, es. risultati_ablation_refined")
    args = parser.parse_args()
    risultati_dir = Path(args.risultati_dir)

    if not risultati_dir.exists():
        print(f"[!] {risultati_dir} non trovata")
        return

    binary_dirs = sorted(
        d for d in risultati_dir.iterdir()
        if d.is_dir() and (d / "vuln_scanner").exists()
    )
    print(f"[*] {len(binary_dirs)} binari trovati in {risultati_dir}")

    regenerated = 0
    skipped = 0

    for i, d in enumerate(binary_dirs, 1):
        binary_name = d.name
        findings_all = d / "vuln_scanner" / "findings_all.json"

        if not findings_all.exists():
            print(f"[!] [{i}/{len(binary_dirs)}] {binary_name}: findings_all.json mancante, salto")
            skipped += 1
            continue

        timing = _load_json(d / "timing.json", None)
        fuzzing_manifest = d / "fuzzing" / "seeds" / "manifest.json"
        decompiled_c = _find_decompiled_c(d)
        # sources/ e ground_truth.json restano SEMPRE nella root del
        # progetto (PROJECT_ROOT/SOURCES_DIR), mai dentro risultati_dir:
        # run_filter_ablation.py copia solo risultati/, queste due
        # restano condivise indipendentemente da quale risultati_dir
        # si sta rigenerando in questo momento.
        source_paths = (
            resolve_source_paths(binary_name, JULIET_MANIFEST_PATH, SOURCES_DIR)
            if JULIET_MANIFEST_PATH.exists() else None
        )

        try:
            generate_report(
                binary_name=binary_name,
                findings_all_json=findings_all,
                output_dir=d / "reporting",
                timing=timing,
                project_root=PROJECT_ROOT,
                fuzzing_manifest_json=fuzzing_manifest if fuzzing_manifest.exists() else None,
                fuzzing_seeds_dir=fuzzing_manifest.parent,
                decompiled_c_path=decompiled_c,
                source_c_paths=source_paths,
            )
            print(f"[+] [{i}/{len(binary_dirs)}] {binary_name}: report rigenerato")
            regenerated += 1
        except Exception as e:
            print(f"[!] [{i}/{len(binary_dirs)}] {binary_name}: errore nella rigenerazione: {e}")
            skipped += 1

    print(f"\n[+] {regenerated} report rigenerati, {skipped} saltati")

    try:
        agg_output = risultati_dir / "aggregate_report.html"
        agg_summary = generate_aggregate_report(risultati_dir, PROJECT_ROOT, agg_output)
        print(f"[+] Report aggregato: {agg_output}")
        if agg_summary["zero_finding_categories"]:
            print(f"[!] Categorie interamente a zero finding: {', '.join(agg_summary['zero_finding_categories'])}")
        if agg_summary["overall_true_positive_rate"] is not None:
            print(f"[*] True positive rate complessivo: {agg_summary['overall_true_positive_rate']:.0%} "
                  f"({agg_summary['binaries_with_ground_truth']} binari con ground truth)")
    except Exception as e:
        print(f"[!] Report aggregato non generato: {e}")


if __name__ == "__main__":
    main()