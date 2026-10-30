"""
reparse_existing.py
--------------------------------------------------------------------
Rigenera comparison.json e il report per ogni binario gia' fuzzato,
ri-analizzando le cartelle campaign_with_seeds/campaign_without_seeds
gia' presenti su disco — SENZA rilanciare AFL++.

Serve dopo la correzione del 27/09 a parse_fuzzer_stats() in
fuzzing_runner.py (bug: in modalita' "-n" fuzzer_stats a volte non
viene scritto; i dati veri (crash/hang/plot_data) sono comunque gia'
su disco, andavano solo riletti col parser corretto).

Uso:
    python reparse_existing.py --risultati-dir risultati_dumb_mode
    python reparse_existing.py --risultati-dir risultati_dumb_mode --only CWE121_..._fgets_01-bad
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fuzzing_runner.fuzzing_runner import parse_fuzzer_stats, build_comparison
from reporting.report_generator import generate_report


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def main() -> None:
    parser = argparse.ArgumentParser(description="Ri-analizza campagne di fuzzing gia' eseguite, senza rilanciare AFL++")
    parser.add_argument("--risultati-dir", required=True)
    parser.add_argument("--only", metavar="NOME_BIN", default=None)
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)
    processed = 0

    for binary_dir in sorted(risultati_dir.iterdir()):
        if not binary_dir.is_dir():
            continue
        if args.only and binary_dir.name != args.only:
            continue

        fuzzing_dir = binary_dir / "fuzzing"
        with_dir = fuzzing_dir / "campaign_with_seeds"
        without_dir = fuzzing_dir / "campaign_without_seeds"
        if not with_dir.exists() and not without_dir.exists():
            continue

        stats_with = parse_fuzzer_stats(with_dir) if with_dir.exists() else {}
        stats_without = parse_fuzzer_stats(without_dir) if without_dir.exists() else {}
        stats_with["binary"] = binary_dir.name
        stats_without["binary"] = binary_dir.name
        stats_with["with_seeds"] = True
        stats_without["with_seeds"] = False

        comparison = build_comparison(stats_with, stats_without)

        comparison_path = fuzzing_dir / "comparison.json"
        comparison_path.write_text(json.dumps({
            "with_seeds": stats_with,
            "without_seeds": stats_without,
            "comparison_table": comparison,
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"\n{'=' * 70}\n{binary_dir.name}\n{'=' * 70}")
        for row in comparison:
            print(f"    {row['metric']:30} con seed: {row['with_seeds']:>10}   senza: {row['without_seeds']:>10}")

        findings_all = binary_dir / "vuln_scanner" / "findings_all.json"
        timing = _load_json(binary_dir / "timing.json", None)
        manifest_json = fuzzing_dir / "seeds" / "manifest.json"

        generate_report(
            binary_name=binary_dir.name,
            findings_all_json=findings_all,
            output_dir=binary_dir / "reporting",
            timing=timing,
            project_root=Path.cwd(),
            fuzzing_manifest_json=manifest_json if manifest_json.exists() else None,
            fuzzing_effectiveness=comparison,
        )
        print(f"[+] {binary_dir.name}: report rigenerato")
        processed += 1

    print(f"\n{'=' * 70}\n[*] {processed} binari ri-analizzati\n{'=' * 70}")


if __name__ == "__main__":
    main()