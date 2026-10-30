"""
semgrep_lungo.py
--------------------------------------------------------------------
Esecuzione singola di Semgrep su un file decompilato grande (pensato
per readelf), con limiti piu' larghi di quelli della pipeline.

Prima versione: Semgrep sul file intero di readelf (2.8 MB) finiva in
16 s con un "Syntax error" sull'intero file e 0 finding: il parser C
rinunciava al file nel suo complesso.

Questa versione divide il decompilato in un file per funzione (una
funzione Ghidra si chiude con "}" in prima colonna), antepone a
ciascuno l'header dei tipi Ghidra e lancia Semgrep una sola volta
sulla cartella. Cosi' un errore di sintassi fa perdere solo la
funzione che lo contiene, non tutto il programma. I numeri di riga
vengono riportati al file originale.

Limiti di Semgrep tolti: --max-target-bytes, --timeout per regola,
--timeout-threshold. Timeout complessivo: 10 minuti (--timeout).

Non modifica nulla della pipeline: riusa solo il file di regole,
l'header dei tipi e la mappa riga -> funzione di
vuln_scanner/semgrep_scanner.py.

Uso (dalla root del progetto):
    python semgrep_lungo.py <percorso_decompiled.c>
    python semgrep_lungo.py <percorso_decompiled.c> --timeout 900
--------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from vuln_scanner.semgrep_scanner import (
    HEADER_PATH,
    RULES_PATH,
    _kill_process_tree,
    _line_to_function,
)


def split_functions(lines: list[str]) -> list[tuple[int, list[str]]]:
    """Divide il file in blocchi che terminano con '}' in prima colonna.
    Ritorna (riga_iniziale_1based, righe_del_blocco)."""
    blocks, start, cur = [], 1, []
    for i, line in enumerate(lines, 1):
        cur.append(line)
        if line.startswith("}"):
            blocks.append((start, cur))
            start, cur = i + 1, []
    if cur:
        blocks.append((start, cur))
    return blocks


def main() -> int:
    parser = argparse.ArgumentParser(description="Semgrep per funzione, con limiti larghi, su un file decompilato")
    parser.add_argument("input", help="File .c decompilato (es. readelf_decompiled.c)")
    parser.add_argument("--timeout", type=int, default=600,
                        help="Tempo massimo complessivo in secondi (default 600 = 10 minuti)")
    parser.add_argument("--output", default="semgrep_lungo_risultato.json",
                        help="File JSON con i finding")
    args = parser.parse_args()

    src = Path(args.input)
    if not src.is_file():
        print(f"[!] file non trovato: {src}")
        return 1

    text = src.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    blocks = split_functions(lines)
    header = HEADER_PATH.read_text(encoding="utf-8")
    if not header.endswith("\n"):
        header += "\n"
    header_lines = header.count("\n")

    print(f"[*] file: {src} ({src.stat().st_size / 1e6:.1f} MB, {len(lines)} righe, {len(blocks)} blocchi)")
    print(f"[*] regole: {RULES_PATH}")
    print(f"[*] timeout complessivo: {args.timeout} s")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        start_of = {}
        for k, (start, blk) in enumerate(blocks):
            name = f"f{k:05d}.c"
            (tmp_dir / name).write_text(header + "".join(blk), encoding="utf-8")
            start_of[name] = start

        cmd = [
            "semgrep",
            "--config", str(RULES_PATH),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--max-target-bytes", "0",
            "--timeout", "0",
            "--timeout-threshold", "0",
            str(tmp_dir),
        ]
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
               "PYTHONIOENCODING": "utf-8"}

        start_t = time.time()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace", env=env)
        try:
            stdout, stderr = proc.communicate(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc.pid)
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
            print(f"[!] Semgrep non ha finito entro {args.timeout} s.")
            return 2
        elapsed = time.time() - start_t

    print(f"[*] Semgrep terminato in {elapsed:.0f} s (codice di uscita {proc.returncode})")
    if not stdout.strip():
        print(f"[!] nessun output da Semgrep. stderr:\n{stderr[:2000]}")
        return 3

    data = json.loads(stdout)
    errors = data.get("errors", [])
    scanned = data.get("paths", {}).get("scanned", [])
    print(f"[*] blocchi analizzati: {len(scanned)} su {len(blocks)}; errori: {len(errors)}")
    syntax = [e for e in errors if "yntax" in str(e.get("type"))]
    if syntax:
        print(f"    di cui errori di sintassi: {len(syntax)} (blocchi persi solo in parte o del tutto)")

    line_to_func = _line_to_function(text)
    findings = []
    for r in data.get("results", []):
        name = Path(r["path"]).name
        line = r["start"]["line"] - header_lines + start_of.get(name, 1) - 1
        meta = r.get("extra", {}).get("metadata", {})
        findings.append({
            "engine": "semgrep",
            "rule": r["check_id"].split(".")[-1],
            "cwe": meta.get("cwe", ""),
            "line": line,
            "function": line_to_func.get(line),
            "code": lines[line - 1].strip() if 0 < line <= len(lines) else "",
        })

    out = Path(args.output)
    out.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] {len(findings)} finding -> {out}")

    per_regola: dict[str, int] = {}
    for f in findings:
        per_regola[f["rule"]] = per_regola.get(f["rule"], 0) + 1
    for regola, n in sorted(per_regola.items(), key=lambda x: -x[1]):
        print(f"    {n:5d}  {regola}")

    nella_cve = [f for f in findings if f["function"] == "print_dynamic_symbol"]
    print(f"\n[*] finding in print_dynamic_symbol: {len(nella_cve)}")
    for f in nella_cve:
        print(f"    riga {f['line']}: {f['rule']} ({f['cwe']})  ->  {f['code'][:100]}")

    # Errori di sintassi che toccano print_dynamic_symbol?
    for e in syntax:
        name = Path(str(e.get("path", ""))).name
        if name in start_of:
            s = start_of[name]
            if line_to_func.get(s + 2) == "print_dynamic_symbol" or "print_dynamic_symbol" in "".join(
                    blocks[int(name[1:6])][1][:5]):
                print(f"[!] errore di sintassi nel blocco di print_dynamic_symbol: {str(e.get('message'))[:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
