"""
run_fuzzing_with_claude_seeds.py
--------------------------------------------------------------------
Terza via di confronto per il fuzzing, oltre a "con seed euristici"
e "senza seed" (gia' fatti da run_fuzzing_campaigns.py): usa i seed
generati da Claude (fuzzing/seeds_claude/, prodotti da
generate_seeds_with_claude.py) come corpus di partenza.

Gira solo sui binari per cui ESISTONO GIA' seed di Claude su disco
E che sono compatibili con l'infrastruttura di fuzzing attuale (solo
canali file/stdin — i binari a socket restano esclusi anche se hanno
seed di Claude, per lo stesso motivo per cui sono esclusi dalle altre
due campagne: servirebbe un wrapper desock/preeny non presente in
questa versione).

Uso:
    python run_fuzzing_with_claude_seeds.py --risultati-dir risultati_ablation_refined --duration 180
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fuzzing_runner.fuzzing_runner import FuzzableTarget, discover_fuzzable_binaries, run_campaign


def main() -> None:
    parser = argparse.ArgumentParser(description="Campagna di fuzzing con i seed generati da Claude")
    parser.add_argument("--risultati-dir", default="risultati")
    parser.add_argument("--duration", type=int, default=180, help="Durata in secondi per binario (default: 180 = 3 minuti)")
    parser.add_argument("--target-args", default="", help="Opzioni da passare al binario, es. '-s'")
    parser.add_argument("--qemu", action="store_true", help="Usa la modalita' QEMU (feedback di copertura)")
    parser.add_argument("--out-name", default="campaign_claude_seeds", help="Nome della cartella di output")
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)

    # riusa la stessa logica di discovery di run_fuzzing_campaigns.py,
    # cosi' l'insieme "compatibile con l'infrastruttura attuale" resta
    # identico e coerente con le altre due campagne — poi filtriamo qui
    # per chi ha DAVVERO dei seed_claude su disco.
    all_fuzzable = discover_fuzzable_binaries(risultati_dir)

    # I seed generati PRIMA di questa correzione usano ancora il vecchio
    # nome (manifest_claude.json) — cerchiamo entrambi, cosi' non serve
    # rigenerare da capo (costo API reale gia' speso) solo per un nome
    # di file diverso.
    eligible = []
    for target in all_fuzzable:
        claude_seeds_dir = target.output_root / "seeds_claude"
        manifest = claude_seeds_dir / "manifest.json"
        if not manifest.exists():
            manifest = claude_seeds_dir / "manifest_claude.json"
        if manifest.exists():
            n_seeds = len(json.loads(manifest.read_text(encoding="utf-8")).get("seeds", []))
            if n_seeds > 0:
                eligible.append(target)

    print(f"[*] {len(eligible)} binari con seed Claude E compatibili con l'infrastruttura di fuzzing attuale")
    if not eligible:
        print("[!] Nessun binario eleggibile — verifica di aver gia' generato i seed con generate_seeds_with_claude.py")
        return

    for i, target in enumerate(eligible, 1):
        print(f"\n{'=' * 70}\n{target.binary_name} (con seed Claude, {args.duration}s)\n{'=' * 70}")

        claude_target = FuzzableTarget(
            binary_name=target.binary_name,
            binary_path=target.binary_path,
            seeds_dir=target.output_root / "seeds_claude",
            kind=target.kind,
            output_root=target.output_root,
        )

        try:
            stats = run_campaign(claude_target, with_seeds=True, duration_seconds=args.duration,
                                 qemu=args.qemu, extra_args=args.target_args.split())
        except Exception as e:
            print(f"[!] {target.binary_name}: errore — {e}")
            continue

        # run_campaign scrive di default in output_root/campaign_with_seeds —
        # la rinomino subito per non confondere con la campagna a seed
        # euristici gia' fatta in precedenza sullo stesso identico percorso.
        default_dir = target.output_root / "campaign_with_seeds"
        claude_dir = target.output_root / args.out_name
        if claude_dir.exists():
            import shutil
            shutil.rmtree(claude_dir)
        if default_dir.exists():
            default_dir.rename(claude_dir)

        print(f"[+] Crash: {stats.get('unique_crashes', 0)} | "
              f"Hang: {stats.get('unique_hangs', 0)} | "
              f"Percorsi unici: {stats.get('paths_total', 0)} | "
              f"Esecuzioni: {stats.get('execs_done', 0)} ({stats.get('execs_per_sec', 0):.1f}/s)")
        print(f"[+] Output in: {claude_dir}")


if __name__ == "__main__":
    main()