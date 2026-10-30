"""
run_fuzzing_campaigns.py
--------------------------------------------------------------------
Script di orchestrazione, stesso stile di rerun_scanning.py e
run_llm_review.py: non rifa' decompile/CFG/vuln_scanner (gia' fatti),
aggiunge SOLO la fase di fuzzing vera e propria, poi rigenera il
report del binario (gia' esistente) includendo il confronto
con/senza seed nella sezione "Fuzzing" gia' pronta ad accoglierlo.

Uso:
    python run_fuzzing_campaigns.py                     # tutti i binari fuzzabili trovati
    python run_fuzzing_campaigns.py --only NOME_BIN      # solo uno
    python run_fuzzing_campaigns.py --duration 300       # 5 minuti a campagna invece del default (120s)
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fuzzing_runner.fuzzing_runner import (
    discover_fuzzable_binaries,
    run_campaign,
    build_comparison,
    FuzzingNotAvailable,
)
from pipe import RISULTATI_DIR
from reporting.report_generator import generate_report


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def run_one(target, duration_seconds: int) -> dict:
    print(f"\n{'=' * 70}\n{target.binary_name} (tipo ingresso: {target.kind})\n{'=' * 70}")

    stats_with = run_campaign(target, with_seeds=True, duration_seconds=duration_seconds)
    stats_without = run_campaign(target, with_seeds=False, duration_seconds=duration_seconds)

    comparison = build_comparison(stats_with, stats_without)

    comparison_path = target.output_root / "comparison.json"
    comparison_path.write_text(json.dumps({
        "with_seeds": stats_with,
        "without_seeds": stats_without,
        "comparison_table": comparison,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] {target.binary_name}: confronto salvato in {comparison_path}")
    for row in comparison:
        print(f"    {row['metric']:30} con seed: {row['with_seeds']:>10}   senza: {row['without_seeds']:>10}")

    # Rigenera il report del binario, ora CON il confronto fuzzing
    # popolato — riusa gli stessi findings/timing/ground_truth gia'
    # su disco, non rilancia vuln_scanner.
    binary_root = target.output_root.parent
    findings_all = binary_root / "vuln_scanner" / "findings_all.json"
    timing = _load_json(binary_root / "timing.json", None)
    manifest_json = target.seeds_dir / "manifest.json"

    generate_report(
        binary_name=target.binary_name,
        findings_all_json=findings_all,
        output_dir=binary_root / "reporting",
        timing=timing,
        project_root=Path.cwd(),
        fuzzing_manifest_json=manifest_json if manifest_json.exists() else None,
        fuzzing_effectiveness=comparison,
    )
    print(f"[+] {target.binary_name}: report rigenerato con il confronto fuzzing incluso")

    return {"binary": target.binary_name, "comparison": comparison}


def main() -> None:
    parser = argparse.ArgumentParser(description="Esegue campagne AFL++ con/senza seed sui binari fuzzabili")
    parser.add_argument("--only", metavar="NOME_BIN", default=None)
    parser.add_argument("--duration", type=int, default=120, help="Secondi per campagna (default: 120)")
    parser.add_argument("--risultati-dir", default=str(RISULTATI_DIR))
    parser.add_argument("--list", action="store_true",
                         help="Elenca solo i binari fuzzabili trovati (con il loro tipo di ingresso), senza lanciare nulla")
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)
    targets = discover_fuzzable_binaries(risultati_dir)

    if args.list:
        print(f"[*] {len(targets)} binari fuzzabili trovati:\n")
        for t in targets:
            n_seeds = sum(1 for _ in t.seeds_dir.rglob("*") if _.is_file() and _.name != "manifest.json")
            print(f"  {t.binary_name:<70} tipo: {t.kind:<15} seed disponibili: {n_seeds}")
        return

    if args.only:
        targets = [t for t in targets if t.binary_name == args.only]
        if not targets:
            print(f"[!] {args.only} non trovato tra i binari fuzzabili (tipo di ingresso non supportato, o assente)")
            return

    print(f"[*] {len(targets)} binari fuzzabili trovati ({args.duration}s per campagna, x2 campagne = "
          f"~{len(targets) * args.duration * 2 // 60} minuti totali stimati)")

    results = []
    try:
        for target in targets:
            results.append(run_one(target, args.duration))
    except FuzzingNotAvailable as e:
        print(f"\n[!] {e}")
        return

    print(f"\n{'=' * 70}\n[*] RIEPILOGO\n{'=' * 70}")
    for r in results:
        crashes_with = next((row["with_seeds"] for row in r["comparison"] if row["metric"] == "Crash trovati"), "?")
        crashes_without = next((row["without_seeds"] for row in r["comparison"] if row["metric"] == "Crash trovati"), "?")
        print(f"  {r['binary']:<60} crash: {crashes_with} (con seed) vs {crashes_without} (senza)")


if __name__ == "__main__":
    main()