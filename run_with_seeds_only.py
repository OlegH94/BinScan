"""
run_with_seeds_only.py
--------------------------------------------------------------------
Rilancia SOLO la campagna "con seed automatici" (campaign_with_seeds)
per uno o piu' binari, senza toccare campaign_without_seeds (che
resta quello gia' ottenuto e verificato in precedenza).

Serve per recuperare campaign_with_seeds dopo che e' stato
sovrascritto da run_fuzzing_with_claude_seeds.py (che riusa lo stesso
nome di cartella prima di rinominarla in campaign_claude_seeds),
senza dover rifare anche la campagna senza seed.

Uso:
    python run_with_seeds_only.py --risultati-dir risultati_dumb_mode --duration 120
    python run_with_seeds_only.py --risultati-dir risultati_dumb_mode --duration 120 --only NOME_BIN
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
from pathlib import Path

from fuzzing_runner.fuzzing_runner import discover_fuzzable_binaries, run_campaign, FuzzingNotAvailable


def main() -> None:
    parser = argparse.ArgumentParser(description="Rilancia solo la campagna con seed automatici")
    parser.add_argument("--risultati-dir", required=True)
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--only", metavar="NOME_BIN", default=None)
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)
    targets = discover_fuzzable_binaries(risultati_dir)

    if args.only:
        targets = [t for t in targets if t.binary_name == args.only]
        if not targets:
            print(f"[!] {args.only} non trovato tra i binari fuzzabili")
            return

    print(f"[*] {len(targets)} binari — solo campagna CON seed automatici, {args.duration}s ciascuno")

    try:
        for target in targets:
            print(f"\n{'=' * 70}\n{target.binary_name}\n{'=' * 70}")
            stats = run_campaign(target, with_seeds=True, duration_seconds=args.duration)
            print(f"[+] Crash: {stats.get('unique_crashes', 0)} | "
                  f"Hang: {stats.get('unique_hangs', 0)} | "
                  f"Percorsi unici: {stats.get('paths_total', 0)} | "
                  f"Esecuzioni: {stats.get('execs_done', 0)} ({stats.get('execs_per_sec', 0):.1f}/s)")
    except FuzzingNotAvailable as e:
        print(f"\n[!] {e}")


if __name__ == "__main__":
    main()