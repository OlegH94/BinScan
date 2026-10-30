"""
concat_vulnllm_results.py
--------------------------------------------------------------------
Concatena in un unico file, per ogni binario, la ground truth attesa
e il verdetto GREZZO di VulnLLM-R (whole_analysis.txt) — SENZA alcuna
classificazione automatica trovato/non-trovato. La classificazione
automatica precedente (compare_vulnllm_ground_truth.py) si e' rivelata
inaffidabile su tutto il batch (l'euristica di estrazione non
generalizza al formato reale su tutti i 144 binari) — meglio un
confronto grezzo leggibile a mano che un numero automatico sbagliato.

Struttura attesa in input:
    <dataset-root>/<nome_binario>/vuln_vulnllm_whole/whole_analysis.txt

Uso:
    python concat_vulnllm_results.py \
        --dataset-root vulnllm_whole_v2_extracted/ref_dataset \
        --ground-truth ground_truth.json \
        --output tutti_verdetti_vulnllm.md
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ANALYSIS_SUBPATH = Path("vuln_vulnllm_whole") / "whole_analysis.txt"


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def concat_all(dataset_root: Path, ground_truth: dict) -> tuple[str, int]:
    binary_dirs = sorted(d for d in dataset_root.iterdir() if d.is_dir())

    blocks = []
    n_with_analysis = 0

    for d in binary_dirs:
        binary_name = d.name
        analysis_path = d / ANALYSIS_SUBPATH
        if not analysis_path.exists():
            continue

        n_with_analysis += 1
        raw_text = analysis_path.read_text(encoding="utf-8", errors="ignore").strip()

        gt_entry = ground_truth.get(binary_name)
        if gt_entry and gt_entry.get("expected"):
            gt_lines = "\n".join(
                f"- `{e.get('cwe')}` — funzione `{e.get('function')}`"
                for e in gt_entry["expected"]
            )
        else:
            gt_lines = "*(nessuna ground truth trovata per questo binario)*"

        block = (
            f"## {binary_name}\n\n"
            f"**Ground truth attesa:**\n{gt_lines}\n\n"
            f"**Verdetto VulnLLM-R:**\n```\n{raw_text}\n```"
        )
        blocks.append(block)

    header = f"# Verdetti VulnLLM-R vs ground truth (confronto grezzo, non classificato)\n\n{n_with_analysis} binari con analisi trovata\n\n---\n\n"
    return header + "\n\n---\n\n".join(blocks), n_with_analysis


def main() -> None:
    parser = argparse.ArgumentParser(description="Concatena i verdetti VulnLLM-R con la ground truth, senza classificazione automatica")
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--ground-truth", default="ground_truth.json")
    parser.add_argument("--output", default="tutti_verdetti_vulnllm.md")
    args = parser.parse_args()

    dataset_root = Path(args.dataset_root)
    if not dataset_root.exists():
        print(f"[!] {dataset_root} non trovata")
        return

    ground_truth = _load_json(Path(args.ground_truth), {})

    output_text, n = concat_all(dataset_root, ground_truth)
    Path(args.output).write_text(output_text, encoding="utf-8")

    print(f"[+] {n} binari concatenati")
    print(f"[+] Scritto in: {args.output}")


if __name__ == "__main__":
    main()