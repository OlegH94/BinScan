"""
crash_report.py
--------------------------------------------------------------------
Genera un report HTML per-binario (tutti i crash trovati su quel
binario, con/senza seed) e uno aggregato su tutto il batch — stesso
stile "autosufficiente, nessun template esterno" gia' usato per il
notebook Colab di llm_reviewer.
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from crash_analyzer.crash_analyzer import CrashReport


def _escape(s) -> str:
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_binary_crash_report_html(binary_name: str, reports: list[CrashReport]) -> str:
    rows = []
    for r in reports:
        corruption_warning = ""
        if r.crash_frame_index is not None and r.crash_frame_index > 0:
            corruption_warning = (
                f'<p style="color:#b71c1c;"><strong>⚠ Backtrace parzialmente illeggibile</strong> — '
                f'il punto di crash immediato (frame #0) non aveva un simbolo risolto, probabile '
                f'corruzione dello stack. La funzione mostrata è stata recuperata dal frame #{r.crash_frame_index}, '
                f'più a monte nella pila di chiamate — attribuzione meno certa di un crash diretto.</p>'
            )

        rows.append(f"""
<div class="crash-entry">
  <p><span class="badge badge-{_escape(r.campaign)}">{_escape(r.campaign)}</span>
     <strong>{_escape(r.crash_file)}</strong></p>
  <p><strong>Segnale:</strong> {_escape(r.signal) or 'n/d'}
     &nbsp; <strong>Indirizzo:</strong> <code>{_escape(r.address) or 'n/d'}</code>
     &nbsp; <strong>Funzione:</strong> <code>{_escape(r.function_name) or 'n/d'}</code></p>
  {corruption_warning}
  <details><summary>Pseudocodice della funzione</summary>
    <pre><code>{_escape(r.pseudocode) if r.pseudocode else '(funzione non trovata nel decompilato)'}</code></pre>
  </details>
  <details><summary>Output completo di gdb</summary>
    <pre><code>{_escape(r.gdb_output)}</code></pre>
  </details>
</div>""")

    n_with = sum(1 for r in reports if r.campaign == "with_seeds")
    n_without = sum(1 for r in reports if r.campaign == "without_seeds")

    return f"""<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8">
<title>Analisi crash — {_escape(binary_name)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background: #fafafa; }}
  .crash-entry {{ background: white; border: 1px solid #ddd; border-left: 4px solid #b71c1c; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }}
  .badge {{ display: inline-block; padding: .1rem .5rem; border-radius: 12px; font-size: .8rem; color: white; }}
  .badge-with_seeds {{ background: #2e7d32; }}
  .badge-without_seeds {{ background: #616161; }}
  pre {{ background: #272822; color: #f8f8f2; padding: .8rem; border-radius: 4px; overflow-x: auto; font-size: .82rem; }}
  .metric-box {{ display: inline-block; background: white; border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.5rem; margin-right: 1rem; text-align: center; }}
  .metric-box .value {{ font-size: 1.8rem; font-weight: bold; display: block; }}
</style></head><body>
<h1>Analisi crash — {_escape(binary_name)}</h1>
<div>
  <div class="metric-box"><span class="value">{len(reports)}</span>crash totali</div>
  <div class="metric-box"><span class="value">{n_with}</span>con seed</div>
  <div class="metric-box"><span class="value">{n_without}</span>senza seed</div>
</div>
{''.join(rows) if rows else '<p>Nessun crash trovato.</p>'}
</body></html>"""


def build_aggregate_crash_report_html(all_reports: dict[str, list[CrashReport]]) -> str:
    """
    all_reports: {nome_binario: [CrashReport, ...]}
    """
    rows = []
    for binary_name, reports in all_reports.items():
        for r in reports:
            rows.append(f"""
<tr>
  <td><a href="{_escape(binary_name)}/fuzzing/crash_analysis.html">{_escape(binary_name)}</a></td>
  <td>{_escape(r.campaign)}</td>
  <td>{_escape(r.signal) or 'n/d'}</td>
  <td><code>{_escape(r.function_name) or 'n/d'}</code></td>
  <td><code>{_escape(r.address) or 'n/d'}</code></td>
</tr>""")

    total_crashes = sum(len(r) for r in all_reports.values())
    binaries_with_crashes = sum(1 for r in all_reports.values() if r)

    return f"""<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8">
<title>Report aggregato crash</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background: #fafafa; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; background: white; }}
  th, td {{ border: 1px solid #ddd; padding: .5rem .7rem; text-align: left; font-size: .9rem; }}
  th {{ background: #333; color: white; }}
  tr:nth-child(even) {{ background: #f4f4f4; }}
  .metric-box {{ display: inline-block; background: white; border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.5rem; margin-right: 1rem; text-align: center; }}
  .metric-box .value {{ font-size: 1.8rem; font-weight: bold; display: block; }}
</style></head><body>
<h1>Report aggregato — crash trovati dal fuzzing</h1>
<div>
  <div class="metric-box"><span class="value">{binaries_with_crashes}</span>binari con almeno un crash</div>
  <div class="metric-box"><span class="value">{total_crashes}</span>crash totali</div>
</div>
<table>
  <tr><th>Binario</th><th>Campagna</th><th>Segnale</th><th>Funzione</th><th>Indirizzo</th></tr>
  {''.join(rows) if rows else '<tr><td colspan="5">Nessun crash trovato in tutto il batch.</td></tr>'}
</table>
</body></html>"""


def write_binary_crash_report(binary_root: Path, binary_name: str, reports: list[CrashReport]) -> None:
    output_dir = binary_root / "fuzzing"
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "crash_analysis.json").write_text(
        json.dumps([asdict(r) for r in reports], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (output_dir / "crash_analysis.html").write_text(
        build_binary_crash_report_html(binary_name, reports), encoding="utf-8"
    )