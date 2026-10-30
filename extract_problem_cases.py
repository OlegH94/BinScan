"""
extract_problem_cases.py
--------------------------------------------------------------------
Trova i binari con falsi negativi (una debolezza attesa dalla ground
truth non trovata da nessun motore) o con falsi positivi (un finding
attribuito a una funzione non presente nella ground truth), ed
estrae per ciascuno il codice sorgente e decompilato della funzione
rilevante — in un unico file Markdown, pronto per la condivisione.

Riusa la STESSA logica di reporting/accuracy.py (compute_accuracy)
per garantire che i casi selezionati corrispondano esattamente a
quello che i report mostrano, invece di reimplementare da zero un
confronto leggermente diverso.

Uso:
    python extract_problem_cases.py
    python extract_problem_cases.py --risultati-dir risultati_ablation_none --output casi_none.md
    python extract_problem_cases.py --only-yara-fp   # solo falsi positivi di YARA, non degli altri motori
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reporting.accuracy import load_ground_truth, compute_accuracy
from reporting.code_context import extract_function_code
from reporting.juliet_ground_truth_importer import resolve_source_paths

PROJECT_ROOT = Path(".")
SOURCES_DIR = Path("sources")
JULIET_MANIFEST_PATH = SOURCES_DIR / "manifest.xml"


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _find_decompiled_c(binary_dir: Path) -> Path | None:
    decompiled_dir = binary_dir / "decompiled_files"
    if not decompiled_dir.is_dir():
        return None
    c_files = sorted(decompiled_dir.glob("*.c"))
    return c_files[0] if c_files else None


def _load_text(path) -> str | None:
    if not path or not Path(path).exists():
        return None
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def _load_source_blob(source_paths: list[Path]) -> str | None:
    if not source_paths:
        return None
    texts = []
    for p in source_paths:
        if Path(p).exists():
            texts.append(Path(p).read_text(encoding="utf-8", errors="ignore"))
    return "\n\n".join(texts) if texts else None


def _format_function_block(title: str, code: str | None) -> str:
    if code:
        return f"### {title}\n```c\n{code.strip()}\n```\n"
    return f"### {title}\n*(non trovata)*\n"


def build_problem_report(
    risultati_dir: Path,
    project_root: Path = PROJECT_ROOT,
    only_yara_fp: bool = False,
) -> tuple[str, int]:
    ground_truth = load_ground_truth(project_root)

    binary_dirs = sorted(
        d for d in risultati_dir.iterdir()
        if d.is_dir() and (d / "vuln_scanner").exists()
    )

    output_blocks = []
    n_binaries_with_problems = 0

    for d in binary_dirs:
        binary_name = d.name
        findings_all = _load_json(d / "vuln_scanner" / "findings_all.json", [])

        result = compute_accuracy(binary_name, findings_all, ground_truth)
        if not result.has_ground_truth:
            continue

        false_positives = result.false_positives
        if only_yara_fp:
            false_positives = [fp for fp in false_positives if fp["engine"] == "yara"]

        if not result.false_negatives and not false_positives:
            continue  # binario pulito, non serve includerlo

        n_binaries_with_problems += 1

        decompiled_text = _load_text(_find_decompiled_c(d))
        source_paths = (
            resolve_source_paths(binary_name, JULIET_MANIFEST_PATH, SOURCES_DIR)
            if JULIET_MANIFEST_PATH.exists() else []
        )
        source_text = _load_source_blob(source_paths)

        block = [f"## {binary_name}\n"]

        if result.false_negatives:
            block.append("**Falsi negativi (attesi dalla ground truth, non trovati da nessun motore):**\n")
            for fn in result.false_negatives:
                block.append(f"- `{fn.cwe}` — funzione attesa: `{fn.function}`")
            block.append("")
            for fn in result.false_negatives:
                block.append(_format_function_block(f"Sorgente — {fn.function}", extract_function_code(source_text, fn.function)))
                block.append(_format_function_block(f"Decompilato — {fn.function}", extract_function_code(decompiled_text, fn.function)))

        if false_positives:
            block.append("**Falsi positivi (finding su funzioni non in ground truth):**\n")
            for fp in false_positives:
                block.append(f"- motore `{fp['engine']}`, regola `{fp['rule']}`, funzione flaggata: `{fp['function']}`")
            block.append("")
            seen_fp_functions = set()
            for fp in false_positives:
                if fp["function"] in seen_fp_functions:
                    continue
                seen_fp_functions.add(fp["function"])
                block.append(_format_function_block(
                    f"Decompilato (flaggata per errore) — {fp['function']}",
                    extract_function_code(decompiled_text, fp["function"]),
                ))

        output_blocks.append("\n".join(block))

    header = (
        f"# Casi problematici — {risultati_dir}\n\n"
        f"{n_binaries_with_problems} binari con almeno un falso negativo o un falso positivo"
        f"{' (solo YARA)' if only_yara_fp else ''}\n\n---\n\n"
    )
    return header + "\n---\n\n".join(output_blocks), n_binaries_with_problems


def main() -> None:
    parser = argparse.ArgumentParser(description="Estrae sorgente/decompilato dei casi problematici (falsi negativi, falsi positivi)")
    parser.add_argument("--risultati-dir", default="risultati")
    parser.add_argument("--output", default="casi_problematici.md")
    parser.add_argument("--only-yara-fp", action="store_true",
                         help="Considera solo i falsi positivi prodotti da YARA (default: qualunque motore)")
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)
    if not risultati_dir.exists():
        print(f"[!] {risultati_dir} non trovata")
        return

    output_text, n = build_problem_report(risultati_dir, PROJECT_ROOT, args.only_yara_fp)
    Path(args.output).write_text(output_text, encoding="utf-8")

    print(f"[+] {n} binari con problemi trovati")
    print(f"[+] Scritto in: {args.output}")


if __name__ == "__main__":
    main()