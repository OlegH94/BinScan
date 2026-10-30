"""
find_unresolved_cwe_checker.py
--------------------------------------------------------------------
Scansiona risultati/*/vuln_scanner/findings_all.json e trova i binari
che hanno ALMENO UN finding di cwe_checker con "function": null —
cioe' quelli colpiti dal bug di risoluzione indirizzo->funzione
appena corretto in cwe_checker_integration.py (risoluzione a
corrispondenza esatta invece che per range).

Scrive l'elenco in un file di testo (un nome binario per riga, stesso
formato di selected_bins.txt) da passare a rerun_scanning.py con
--from-file, per rilanciare SOLO questi binari invece di tutto il
batch.

Uso:
    python find_unresolved_cwe_checker.py
    python find_unresolved_cwe_checker.py --output affected_bins.txt
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

RISULTATI_DIR = Path("risultati")


def find_affected_binaries(risultati_dir: Path = RISULTATI_DIR) -> list[str]:
    affected = []

    for binary_dir in sorted(risultati_dir.iterdir()):
        findings_path = binary_dir / "vuln_scanner" / "findings_all.json"
        if not findings_path.exists():
            continue

        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue

        has_unresolved = any(
            f.get("engine") == "cwe_checker" and f.get("function") is None
            for f in findings
        )
        if has_unresolved:
            affected.append(binary_dir.name)

    return affected


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trova i binari con finding cwe_checker non risolti a una funzione")
    parser.add_argument("--risultati-dir", default=str(RISULTATI_DIR), help="Cartella risultati/ (default: risultati)")
    parser.add_argument("--output", default="affected_bins.txt", help="File di output (default: affected_bins.txt)")
    args = parser.parse_args()

    affected = find_affected_binaries(Path(args.risultati_dir))

    Path(args.output).write_text("\n".join(affected) + ("\n" if affected else ""), encoding="utf-8")
    print(f"[+] {len(affected)} binari con finding cwe_checker non risolti -> {args.output}")
    for name in affected:
        print(f"    - {name}")