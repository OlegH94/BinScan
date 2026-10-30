"""
three_way_comparison.py
--------------------------------------------------------------------
Confronto a tre vie per un singolo binario: seed automatici
(campaign_with_seeds), seed generati da un LLM/Claude
(campaign_claude_seeds), nessun seed (campaign_without_seeds).

Pensato per CWE121_..._fgets_01-bad, al momento l'unico binario con
seed Claude gia' generati. Non modifica comparison.json ne' il report
standard (che restano a 2 vie e uniformi su tutti i binari) — produce
un file JSON separato (comparison_3way.json) e una tabella testuale,
pensati per la sezione 6.6.3 della tesi.

Uso:
    python three_way_comparison.py --risultati-dir risultati_dumb_mode --binario CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01-bad
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fuzzing_runner.fuzzing_runner import parse_fuzzer_stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Confronto a 3 vie: seed automatici / seed Claude / nessun seed")
    parser.add_argument("--risultati-dir", required=True)
    parser.add_argument("--binario", required=True, metavar="NOME_BIN")
    args = parser.parse_args()

    fuzzing_dir = Path(args.risultati_dir) / args.binario / "fuzzing"

    variants = {
        "seed_automatici": fuzzing_dir / "campaign_with_seeds",
        "seed_claude": fuzzing_dir / "campaign_claude_seeds",
        "senza_seed": fuzzing_dir / "campaign_without_seeds",
    }

    stats: dict[str, dict | None] = {}
    for label, path in variants.items():
        if path.exists():
            stats[label] = parse_fuzzer_stats(path)
        else:
            print(f"[!] {label}: cartella non trovata ({path}), salto")
            stats[label] = None

    out_path = fuzzing_dir / "comparison_3way.json"
    out_path.write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")

    order = ["seed_automatici", "seed_claude", "senza_seed"]
    headers = ["Seed automatici", "Seed Claude", "Senza seed"]

    print(f"\n{'Metrica':30} " + " ".join(f"{h:>16}" for h in headers))
    metrics = [
        ("Crash trovati", "unique_crashes"),
        ("Hang trovati", "unique_hangs"),
        ("Percorsi unici", "paths_total"),
        ("Esecuzioni totali", "execs_done"),
        ("Esecuzioni al secondo", "execs_per_sec"),
    ]
    for label, key in metrics:
        row = []
        for v in order:
            if stats[v] is None:
                row.append("-")
            else:
                val = stats[v].get(key, 0)
                row.append(f"{val:.1f}" if isinstance(val, float) else str(val))
        print(f"{label:30} " + " ".join(f"{c:>16}" for c in row))

    print(f"\n[+] Salvato in {out_path}")


if __name__ == "__main__":
    main()