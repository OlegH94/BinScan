"""
aggregate_3way.py
--------------------------------------------------------------------
Combina i comparison_3way.json di piu' binari (prodotti da
three_way_comparison.py) in un'unica tabella aggregata per il
capitolo 6: una riga per binario, confronto tra seed automatici,
seed generati da un LLM (Claude) e nessun seed.

Uso:
    python aggregate_3way.py --risultati-dir risultati_dumb_mode
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--risultati-dir", required=True)
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)
    rows: list[tuple[str, dict]] = []

    for binary_dir in sorted(risultati_dir.iterdir()):
        if not binary_dir.is_dir():
            continue
        path = binary_dir / "fuzzing" / "comparison_3way.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        rows.append((binary_dir.name, data))

    if not rows:
        print("[!] Nessun comparison_3way.json trovato — lancia prima three_way_comparison.py su ogni binario")
        return

    out_json = risultati_dir / "aggregate_3way.json"
    out_json.write_text(json.dumps(dict(rows), indent=2, ensure_ascii=False), encoding="utf-8")

    def g(data: dict, variant: str, key: str):
        d = data.get(variant)
        if not d:
            return "-"
        val = d.get(key, "-")
        return f"{val:.1f}" if isinstance(val, float) else str(val)

    print(f"\n{'Binario':<12} {'Crash auto':>11} {'Crash Claude':>13} {'Crash no-seed':>14} "
          f"{'Hang auto':>10} {'Hang Claude':>12} {'Hang no-seed':>13}")
    for name, data in rows:
        short = name.replace("CWE121_Stack_Based_Buffer_Overflow__CWE129_", "")
        print(f"{short:<12} "
              f"{g(data,'seed_automatici','unique_crashes'):>11} {g(data,'seed_claude','unique_crashes'):>13} {g(data,'senza_seed','unique_crashes'):>14} "
              f"{g(data,'seed_automatici','unique_hangs'):>10} {g(data,'seed_claude','unique_hangs'):>12} {g(data,'senza_seed','unique_hangs'):>13}")

    totals = {"seed_automatici": 0, "seed_claude": 0, "senza_seed": 0}
    for name, data in rows:
        for variant in totals:
            d = data.get(variant)
            if d:
                totals[variant] += d.get("unique_crashes", 0)
    print(f"\n{'TOTALE crash':<12} {totals['seed_automatici']:>11} {totals['seed_claude']:>13} {totals['senza_seed']:>14}")

    print("\n--- Tabella LaTeX (crash trovati) ---\n")
    print(r"\begin{table}[h]")
    print(r"\centering")
    print(r"\begin{tabular}{lccc}")
    print(r"\toprule")
    print(r"Binario & Crash (seed automatici) & Crash (seed Claude) & Crash (senza seed) \\")
    print(r"\midrule")
    for name, data in rows:
        short = name.replace("CWE121_Stack_Based_Buffer_Overflow__CWE129_", "").replace("_", r"\_")
        print(f"{short} & {g(data,'seed_automatici','unique_crashes')} & {g(data,'seed_claude','unique_crashes')} & {g(data,'senza_seed','unique_crashes')} \\\\")
    print(r"\midrule")
    print(f"\\textbf{{Totale}} & \\textbf{{{totals['seed_automatici']}}} & \\textbf{{{totals['seed_claude']}}} & \\textbf{{{totals['senza_seed']}}} \\\\")
    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\caption{Crash trovati per ciascun binario fuzzabile, a confronto tra seed strutturali automatici, seed generati da un LLM (Claude) con ragionamento semantico esplicito, e nessun seed mirato (modalit\`a nativa senza QEMU, 120 secondi per campagna).}")
    print(r"\label{tab:fuzzing-3way}")
    print(r"\end{table}")

    print(f"\n[+] Salvato in {out_json}")


if __name__ == "__main__":
    main()