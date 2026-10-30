"""
rerun_yara_only.py
--------------------------------------------------------------------
Riesegue SOLO il motore YARA (vuln_scanner/scanner.py) su tutti i
binari gia' decompilati, senza rilanciare semgrep o cwe_checker
(indipendenti l'uno dall'altro — un fix in scanner.py non li tocca)
— poi rimerge findings_all.json usando i risultati YARA freschi
insieme a quelli semgrep/cwe_checker gia' su disco, senza toccare
Docker.

Utile dopo una correzione che riguarda SOLO scanner.py (come
check_unrolled_copy_overflow): molto piu' veloce di
rerun_scanning.py, che rilancerebbe anche gli altri due motori senza
motivo, con relativo overhead di avvio dei container Docker.

Dopo questo script, rilancia regenerate_reports.py per aggiornare
i report con i findings_all.json freschi.

Uso:
    python rerun_yara_only.py
    python rerun_yara_only.py --risultati-dir risultati_ablation_refined
    python rerun_yara_only.py --only NOME_BIN
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from vuln_scanner.scanner import run_scan, RULES_PATH


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"[!] {path} non e' JSON valido, ignorato")
        return default


def _find_decompiled_c(binary_dir: Path) -> Path | None:
    decompiled_dir = binary_dir / "decompiled_files"
    if not decompiled_dir.is_dir():
        return None
    c_files = sorted(decompiled_dir.glob("*.c"))
    return c_files[0] if c_files else None


def rerun_yara_for_binary(binary_dir: Path, rules_path: str | Path = RULES_PATH) -> dict:
    binary_name = binary_dir.name
    decompiled_c = _find_decompiled_c(binary_dir)
    if decompiled_c is None:
        return {"binary": binary_name, "ok": False, "reason": "decompiled.c mancante"}

    vuln_scanner_dir = binary_dir / "vuln_scanner"
    vuln_scanner_dir.mkdir(parents=True, exist_ok=True)

    yara_findings = run_scan(decompiled_c, vuln_scanner_dir / "findings_yara.json", rules_path)
    # Il dataclass Finding di scanner.py non ha mai avuto un campo
    # "engine" di suo (accuracy.py compensa con .get("engine", "yara")
    # per compatibilita' con i vecchi file) — qui lo aggiungiamo
    # esplicitamente invece di affidarci a quel default implicito,
    # dato che stiamo scrivendo noi stessi il merge finale.
    yara_dicts = [dict(asdict(f), engine="yara") for f in yara_findings]

    # semgrep/cwe_checker sono indipendenti da questo fix: si riusano
    # cosi' come sono gia' su disco, senza rilanciare nulla.
    semgrep_findings = _load_json(vuln_scanner_dir / "findings_semgrep.json", [])
    cwe_checker_findings = _load_json(vuln_scanner_dir / "findings_cwe_checker.json", [])

    findings_all = yara_dicts + semgrep_findings + cwe_checker_findings
    (vuln_scanner_dir / "findings_all.json").write_text(
        json.dumps(findings_all, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    return {
        "binary": binary_name,
        "ok": True,
        "yara": len(yara_dicts),
        "semgrep": len(semgrep_findings),
        "cwe_checker": len(cwe_checker_findings),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Riesegue solo YARA, riusando semgrep/cwe_checker gia' su disco")
    parser.add_argument("--risultati-dir", default="risultati")
    parser.add_argument("--only", metavar="NOME_BIN", default=None)
    parser.add_argument("--rules", default=str(RULES_PATH), help="Path alle regole YARA (default: quello di scanner.py)")
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)
    if not risultati_dir.exists():
        print(f"[!] {risultati_dir} non trovata")
        return

    if args.only:
        binary_dirs = [risultati_dir / args.only]
    else:
        binary_dirs = sorted(
            d for d in risultati_dir.iterdir()
            if d.is_dir() and (d / "vuln_scanner").exists()
        )

    print(f"[*] {len(binary_dirs)} binari da riprocessare (solo YARA) in {risultati_dir}")

    results = []
    for i, d in enumerate(binary_dirs, 1):
        r = rerun_yara_for_binary(d, args.rules)
        results.append(r)
        if r["ok"]:
            print(f"[+] [{i}/{len(binary_dirs)}] {r['binary']}: "
                  f"yara={r['yara']}, semgrep={r['semgrep']}, cwe_checker={r['cwe_checker']}")
        else:
            print(f"[!] [{i}/{len(binary_dirs)}] {r['binary']}: {r['reason']}")

    ok_count = sum(1 for r in results if r["ok"])
    print(f"\n[+] {ok_count}/{len(binary_dirs)} binari riprocessati correttamente")
    print("[*] Ora lancia regenerate_reports.py per aggiornare i report con questi dati.")


if __name__ == "__main__":
    main()