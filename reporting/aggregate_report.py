"""
aggregate_report.py
--------------------------------------------------------------------
Vista d'insieme su TUTTI i binari gia' processati in risultati/, una
riga per binario — pensato per batch di decine/centinaia di binari
(come i 142 Juliet), dove aprire un report.html alla volta non e'
praticabile per farsi un'idea generale.

Riusa la stessa logica di accuracy.py (niente duplicazione): per ogni
binario con una entry in ground_truth.json, calcola TP/FN esattamente
come fa report_generator.py per il report individuale, cosi' i numeri
combaciano sempre tra vista aggregata e vista per-binario.

La "categoria" di un binario e' dedotta dal nome file (tra
"..._Overflow__" e il numero di variante finale) — la stessa
convenzione usata per raggruppare i 3100 binari CWE-121 in 74
categorie durante la selezione del campione: utile per notare in un
colpo d'occhio se gli zero-finding si concentrano su una categoria
specifica (probabile bug di pattern/regex) o sono sparsi a caso.

Uso:
    from reporting.aggregate_report import generate_aggregate_report
    generate_aggregate_report("risultati", ".", "risultati/aggregate_report.html")
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

try:
    from .accuracy import load_ground_truth, compute_accuracy
    from .chart_svg import bar_chart_svg
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from accuracy import load_ground_truth, compute_accuracy
    from chart_svg import bar_chart_svg

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Stessa convenzione usata per raggruppare i 3100 binari CWE-121 in
# categorie durante la selezione del campione (vedi selected_bins.txt).
_CATEGORY_RE = re.compile(r"^CWE121_Stack_Based_Buffer_Overflow__(.+?)_\d+[a-z]?-(bad|good)$")


def _extract_category(binary_name: str) -> str:
    m = _CATEGORY_RE.match(binary_name)
    return m.group(1) if m else binary_name


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _binary_row(binary_dir: Path, ground_truth: dict) -> dict:
    binary_name = binary_dir.name

    findings_all = _load_json(binary_dir / "vuln_scanner" / "findings_all.json", [])
    engine_counts: dict[str, int] = {"yara": 0, "semgrep": 0, "cwe_checker": 0}
    for f in findings_all:
        engine = f.get("engine", "yara")
        engine_counts[engine] = engine_counts.get(engine, 0) + 1

    timing = _load_json(binary_dir / "timing.json", None)

    accuracy = compute_accuracy(binary_name, findings_all, ground_truth)

    total_findings = sum(engine_counts.values())

    return {
        "binary": binary_name,
        "category": _extract_category(binary_name),
        "yara": engine_counts.get("yara", 0),
        "semgrep": engine_counts.get("semgrep", 0),
        "cwe_checker": engine_counts.get("cwe_checker", 0),
        "total_findings": total_findings,
        "all_zero": total_findings == 0,
        "has_ground_truth": accuracy.has_ground_truth,
        "expected_count": len(accuracy.expected),
        "true_positives": len(accuracy.true_positives),
        "false_negatives": len(accuracy.false_negatives),
        "false_positives": len(accuracy.false_positives),
        "decompile_seconds": timing.get("decompile_seconds") if timing else None,
        "cfg_seconds": timing.get("cfg_seconds") if timing else None,
        "report_path": f"{binary_name}/reporting/report.html",
    }


def generate_aggregate_report(
    risultati_dir: str | Path,
    project_root: str | Path,
    output_path: str | Path,
) -> dict:
    """
    Scansiona risultati_dir (una sottocartella per binario, stessa
    struttura scritta da pipe.py) e genera un unico
    aggregate_report.html con una riga per binario.

    Ritorna un riepilogo (utile per un log rapido a fine generazione).
    """
    risultati_dir = Path(risultati_dir)
    ground_truth = load_ground_truth(project_root)

    binary_dirs = sorted(
        d for d in risultati_dir.iterdir()
        if d.is_dir() and (d / "vuln_scanner").exists()
    )

    rows = [_binary_row(d, ground_truth) for d in binary_dirs]

    # Categorie dove TUTTI i binari di quella categoria sono a zero
    # finding totali: il segnale piu' utile per capire dove concentrare
    # il lavoro sulle regole, molto piu' di guardare riga per riga.
    by_category: dict[str, list[dict]] = {}
    for r in rows:
        by_category.setdefault(r["category"], []).append(r)

    zero_categories = sorted(
        cat for cat, cat_rows in by_category.items()
        if all(r["all_zero"] for r in cat_rows)
    )

    with_gt = [r for r in rows if r["has_ground_truth"]]
    total_expected = sum(r["expected_count"] for r in with_gt)
    total_tp = sum(r["true_positives"] for r in with_gt)
    total_fp = sum(r["false_positives"] for r in with_gt)
    overall_tpr = (total_tp / total_expected) if total_expected else None

    summary = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total_binaries": len(rows),
        "zero_finding_binaries": sum(1 for r in rows if r["all_zero"]),
        "zero_finding_categories": zero_categories,
        "binaries_with_ground_truth": len(with_gt),
        "overall_true_positive_rate": overall_tpr,
        "total_false_positives": total_fp,
        "engine_totals": {
            "yara": sum(r["yara"] for r in rows),
            "semgrep": sum(r["semgrep"] for r in rows),
            "cwe_checker": sum(r["cwe_checker"] for r in rows),
        },
    }

    # Due grafici d'insieme per farsi un'idea "a colpo d'occhio" su
    # tutto il batch, invece di dover scorrere la tabella riga per
    # riga: quanti finding ha trovato ciascun motore in totale, e come
    # si distribuiscono TP/FN/FP sui binari che hanno una ground truth
    # annotata. Entrambi tornano None (niente da disegnare) se non
    # c'e' nessun dato, e il template li omette in quel caso.
    engine_chart_svg = bar_chart_svg(summary["engine_totals"])
    accuracy_chart_svg = None
    if with_gt:
        accuracy_chart_svg = bar_chart_svg({
            "veri positivi": total_tp,
            "falsi negativi": sum(r["false_negatives"] for r in with_gt),
            "falsi positivi": total_fp,
        })

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("aggregate_report.html.jinja2")
    html = template.render(
        summary=summary,
        rows=rows,
        engine_chart_svg=engine_chart_svg,
        accuracy_chart_svg=accuracy_chart_svg,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    return summary


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Genera un report aggregato su tutti i binari in risultati/")
    parser.add_argument("--risultati-dir", default="risultati", help="Cartella risultati/ (default: risultati)")
    parser.add_argument("--project-root", default=".", help="Root del progetto, per trovare ground_truth.json (default: .)")
    parser.add_argument("--output", default="risultati/aggregate_report.html", help="Path del report da scrivere")
    args = parser.parse_args()

    summary = generate_aggregate_report(args.risultati_dir, args.project_root, args.output)
    print(f"[+] Report aggregato: {summary['total_binaries']} binari -> {args.output}")
    print(f"[*] Binari a zero finding totali: {summary['zero_finding_binaries']}")
    if summary["zero_finding_categories"]:
        print(f"[!] Categorie interamente a zero: {', '.join(summary['zero_finding_categories'])}")
    if summary["overall_true_positive_rate"] is not None:
        print(f"[*] True positive rate complessivo: {summary['overall_true_positive_rate']:.0%} "
              f"({summary['binaries_with_ground_truth']} binari con ground truth)")