"""
analyze_crashes.py
--------------------------------------------------------------------
Script di orchestrazione, stesso stile di run_fuzzing_campaigns.py:
scansiona tutti i binari gia' fuzzati (con campaign_with_seeds/ e/o
campaign_without_seeds/ presenti), analizza ogni crash trovato via
gdb, e produce un report per binario piu' uno aggregato su tutto il
batch.

Uso:
    python analyze_crashes.py                     # tutti i binari già fuzzati
    python analyze_crashes.py --only NOME_BIN      # solo uno
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
from pathlib import Path

from crash_analyzer.crash_analyzer import analyze_all_crashes, GdbNotAvailable
from crash_analyzer.crash_report import write_binary_crash_report, build_aggregate_crash_report_html
from pipe import RISULTATI_DIR


def _discover_fuzzed_binaries(risultati_dir: Path) -> list[str]:
    return sorted(
        d.name for d in risultati_dir.iterdir()
        if d.is_dir() and (
            (d / "fuzzing" / "campaign_with_seeds").exists()
            or (d / "fuzzing" / "campaign_without_seeds").exists()
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Analizza tutti i crash trovati dal fuzzing via gdb")
    parser.add_argument("--only", metavar="NOME_BIN", default=None)
    parser.add_argument("--risultati-dir", default=str(RISULTATI_DIR))
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)
    binary_names = [args.only] if args.only else _discover_fuzzed_binaries(risultati_dir)

    print(f"[*] {len(binary_names)} binari gia' fuzzati trovati")

    all_reports: dict[str, list] = {}

    try:
        for binary_name in binary_names:
            binary_root = risultati_dir / binary_name
            print(f"\n{'=' * 70}\n{binary_name}\n{'=' * 70}")

            reports = analyze_all_crashes(binary_root, binary_name)
            all_reports[binary_name] = reports

            if reports:
                write_binary_crash_report(binary_root, binary_name, reports)
                print(f"[+] {len(reports)} crash analizzati -> {binary_root / 'fuzzing' / 'crash_analysis.html'}")
            else:
                print("[=] Nessun crash trovato per questo binario")
    except GdbNotAvailable as e:
        print(f"\n[!] {e}")
        return

    agg_html = build_aggregate_crash_report_html(all_reports)
    agg_path = risultati_dir / "aggregate_crash_report.html"
    agg_path.write_text(agg_html, encoding="utf-8")

    total_crashes = sum(len(r) for r in all_reports.values())
    print(f"\n{'=' * 70}\n[*] RIEPILOGO\n{'=' * 70}")
    print(f"[+] {total_crashes} crash totali analizzati su {len(binary_names)} binari")
    print(f"[+] Report aggregato: {agg_path}")


if __name__ == "__main__":
    main()