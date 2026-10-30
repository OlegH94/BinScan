"""
run_readelf_fuzzing.py
--------------------------------------------------------------------
Lancia le due campagne AFL++ (con seed / senza seed) su readelf,
livello di filtro "refined", con il fix "-s" applicato via extra_args
(patch di fuzzing_runner.py: vedi fuzzing_runner_PATCH.md).

Presuppone che fuzzing_runner.py sia gia' patchato con il parametro
extra_args in run_campaign(), e che sia importabile da questa cartella
(mettilo nella stessa directory, o aggiungi il path giusto qui sotto).

Uso:
    python run_readelf_fuzzing.py
    python run_readelf_fuzzing.py --duration 1800
--------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from fuzzing_runner import discover_fuzzable_binaries, run_campaign, build_comparison


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--risultati-dir",
        default=r"risultati_readelf_ablation_refined",
        help="Cartella con readelf gia' scansionato a livello 'refined' "
             "(default: risultati_readelf_ablation_refined)",
    )
    parser.add_argument("--duration", type=int, default=1800,
                         help="Durata in secondi per OGNI campagna (default 1800 = 30 min)")
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)
    targets = discover_fuzzable_binaries(risultati_dir)

    readelf_target = next((t for t in targets if t.binary_name == "readelf"), None)
    if readelf_target is None:
        print(f"[!] readelf non trovato tra i target fuzzabili in {risultati_dir}.")
        print(f"    Target trovati: {[t.binary_name for t in targets]}")
        print("    Controlla che risultati_readelf_ablation_refined\\readelf\\bin\\readelf esista "
              "e che manifest.json abbia kind='file' per la prima entry.")
        return

    print(f"[*] Target: {readelf_target.binary_name}")
    print(f"[*] Binario: {readelf_target.binary_path}")
    print(f"[*] Seed dir: {readelf_target.seeds_dir}")
    print(f"[*] Durata per campagna: {args.duration}s ({args.duration / 60:.0f} min)\n")

    print("=" * 70)
    print("CAMPAGNA CON SEED (seeds_claude + seeds framework)")
    print("=" * 70)
    stats_with = run_campaign(
        readelf_target,
        with_seeds=True,
        duration_seconds=args.duration,
        extra_args=["-s"],
    )
    print(json.dumps(stats_with, indent=2))

    print("\n" + "=" * 70)
    print("CAMPAGNA SENZA SEED (baseline, seed banale)")
    print("=" * 70)
    stats_without = run_campaign(
        readelf_target,
        with_seeds=False,
        duration_seconds=args.duration,
        extra_args=["-s"],
    )
    print(json.dumps(stats_without, indent=2))

    print("\n" + "=" * 70)
    print("CONFRONTO")
    print("=" * 70)
    comparison = build_comparison(stats_with, stats_without)
    for row in comparison:
        print(f"  {row['metric']:30s}  con_seed={row['with_seeds']:>10}  senza_seed={row['without_seeds']:>10}")

    out_file = Path("readelf_fuzzing_comparison.json")
    out_file.write_text(json.dumps({
        "with_seeds": stats_with,
        "without_seeds": stats_without,
        "comparison": comparison,
    }, indent=2), encoding="utf-8")
    print(f"\n[+] Salvato: {out_file.resolve()}")
    print(f"[*] Controlla anche: {readelf_target.output_root}\\campaign_with_seeds\\default\\crashes")
    print(f"[*] Controlla anche: {readelf_target.output_root}\\campaign_without_seeds\\default\\crashes")


if __name__ == "__main__":
    main()