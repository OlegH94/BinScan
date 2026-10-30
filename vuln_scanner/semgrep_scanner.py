"""
semgrep_scanner.py
--------------------------------------------------------------------
Secondo motore di scansione, eseguito IN PARALLELO a YARA
(scanner.py) e alla taint analysis fatta a mano (taint_analysis.py),
non al loro posto. Usa semgrep (parsing AST reale via tree-sitter)
sia per i pattern "candidati" sia per un taint tracking NATIVO
indipendente dal mio taint_analysis.py — utile in tesi per mostrare
dove i due approcci (regex+euristica fatta a mano vs motore di taint
di un tool maturo) concordano o divergono sugli stessi test case.

Lo pseudocodice Ghidra usa typedef non standard (undefined4, uint,
code, ...): senza dichiararli da qualche parte, il parser di semgrep
fallisce silenziosamente su intere funzioni. Per questo ogni file
viene concatenato in memoria con ghidra_types.h prima dell'analisi,
e gli offset di riga nei risultati vengono ricorretti sottraendo le
righe dell'header (vedi _prepend_ghidra_header / _HEADER_LINES).

Richiede semgrep installato: pip install semgrep (vedi requirements.txt).
Uso da libreria (stessa forma di scanner.run_scan):
    from vuln_scanner.semgrep_scanner import run_semgrep_scan
    findings = run_semgrep_scan(decompiled_c_path, output_json_path)
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RULES_PATH = Path(__file__).parent / "semgrep_rules" / "buffer_overflow.yml"
HEADER_PATH = Path(__file__).parent / "ghidra_types.h"

_HEADER_LINES = HEADER_PATH.read_text(encoding="utf-8").count("\n")


class SemgrepNotAvailable(RuntimeError):
    """semgrep non è installato/nel PATH."""


def _check_semgrep_available() -> None:
    if shutil.which("semgrep") is None:
        raise SemgrepNotAvailable(
            "semgrep non trovato nel PATH. Installa con: pip install semgrep"
        )


def _prepend_ghidra_header(source_path: Path, tmp_dir: Path) -> Path:
    """
    Scrive in tmp_dir una copia di source_path con ghidra_types.h
    anteposto, cosi' il parser di semgrep riconosce i typedef Ghidra.
    Ritorna il path del file temporaneo.
    """
    header_text = HEADER_PATH.read_text(encoding="utf-8")
    source_text = source_path.read_text(encoding="utf-8", errors="ignore")

    tmp_file = tmp_dir / source_path.name
    tmp_file.write_text(header_text + source_text, encoding="utf-8")
    return tmp_file


def _kill_process_tree(pid: int) -> None:
    """
    Su Windows, Popen.kill()/subprocess.run(timeout=...) termina SOLO
    il processo principale, non i suoi eventuali figli — se semgrep
    (scritto in Python) avvia worker interni, questi possono restare
    vivi e tenere aperta la pipe di output: il thread di lettura dello
    stdout resta bloccato per sempre in attesa che si chiuda, ANCHE
    DOPO che il timeout e' scattato correttamente (bug osservato in
    produzione: TimeoutExpired sollevato dopo 30s come previsto, ma
    poi subprocess.run() si e' bloccato a sua volta nella propria
    pulizia interna, in attesa del thread di lettura).

    taskkill /T termina l'intero albero di processi con quel PID come
    radice, non solo il processo principale — su piattaforme diverse
    da Windows usa semplicemente kill() (comportamento gia' corretto
    li', il problema e' specifico dei processi Windows).
    """
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
        )
    else:
        import signal
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _run_semgrep_on_file(target_file: Path, rules_path: Path, timeout_seconds: int = 30) -> list[dict]:
    cmd = [
        "semgrep",
        "--config", str(rules_path),
        "--json",
        "--metrics=off",
        "--quiet",
        "--disable-version-check",  # prova diretta del blocco: "semgrep --version" stampa
                                     # da solo un avviso di aggiornamento disponibile, cioe'
                                     # fa una chiamata di rete ad ogni invocazione — le sole
                                     # variabili d'ambiente sotto non bastavano su questa
                                     # versione (1.173.0), il flag esplicito e' piu' diretto
        str(target_file),
    ]

    # Al primo avvio su una macchina, semgrep puo' fare un controllo di
    # rete (versione/telemetria) che si blocca a lungo dietro firewall
    # aziendali o con connessioni lente — --metrics=off da solo non lo
    # disabilita sempre del tutto su tutte le versioni. Queste due env
    # var lo disattivano esplicitamente; il timeout sotto resta comunque
    # come rete di sicurezza se anche questo non bastasse.
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print(f"[!] semgrep non ha risposto entro {timeout_seconds}s su {target_file}: "
              f"salto questo file e proseguo (probabile blocco di rete al primo avvio — "
              f"prova a lanciare semgrep da riga di comando sullo stesso file per isolare il problema)",
              flush=True)

        _kill_process_tree(proc.pid)

        # Dopo aver forzato la terminazione dell'intero albero, un
        # secondo communicate() con un timeout breve dovrebbe ora
        # sbloccarsi (le pipe sono davvero chiuse); se anche questo
        # dovesse bloccarsi (caso limite estremo), rinunciamo comunque
        # a leggere l'output invece di restare appesi una seconda volta.
        try:
            proc.communicate(timeout=5)
        except Exception:
            pass

        return []

    if not stdout.strip():
        print(f"[!] semgrep non ha prodotto output per {target_file}: {stderr[:500]}", flush=True)
        return []

    data = json.loads(stdout)
    return data.get("results", [])


def _normalize_result(raw: dict, filename: str) -> dict:
    """
    Converte un risultato semgrep grezzo nello stesso schema (a
    grandi linee) dei Finding di scanner.py, cosi' i due output si
    possono confrontare/unire facilmente.
    """
    meta = raw.get("extra", {}).get("metadata", {})
    line_in_original = raw["start"]["line"] - _HEADER_LINES

    return {
        "engine": "semgrep",
        "rule": raw["check_id"].split(".")[-1],
        "description": raw.get("extra", {}).get("message", ""),
        "severity": raw.get("extra", {}).get("severity", "WARNING"),
        "cwe": meta.get("cwe", ""),
        "file": filename,
        "line": line_in_original,
        "is_taint_rule": "tainted" in raw["check_id"],
        "engine_note": meta.get("engine_note", ""),
    }


def _line_to_function(text: str) -> dict:
    """
    Mappa numero di riga (1-based, nel file decompilato ORIGINALE, senza
    header) -> nome della funzione che contiene quella riga. Serve a dare
    ai finding di semgrep il campo "function", senza il quale il confronto
    con la ground truth (reporting/accuracy.py, che lavora per funzione)
    non li conta ne' come veri ne' come falsi positivi. Stesso principio
    della risoluzione indirizzo->funzione di cwe_checker, applicato alle
    righe: Ghidra apre e chiude ogni funzione con una graffa in prima
    colonna.
    """
    import re as _re
    lines = text.split("\n")
    out: dict = {}
    current = None
    for i, line in enumerate(lines):
        if line.startswith("{") and current is None:
            j = i - 1
            while j >= 0 and not lines[j].strip():
                j -= 1
            signature = ""
            while j >= 0 and lines[j].strip() and not lines[j].startswith("}"):
                signature = lines[j] + " " + signature
                j -= 1
            m = _re.search(r"([A-Za-z_]\w*)\s*\(", signature)
            current = m.group(1) if m else None
            for k in range(j + 1, i + 1):
                out[k + 1] = current
        elif line.startswith("}"):
            out[i + 1] = current
            current = None
        elif current is not None:
            out[i + 1] = current
    return out


def run_semgrep_scan(
    input_path: str | Path,
    output_json: str | Path,
    rules_path: str | Path = RULES_PATH,
) -> list[dict]:
    """
    Scansiona `input_path` (file o cartella di pseudocodice .c) con
    semgrep, scrive il risultato normalizzato in `output_json` e
    ritorna la lista di finding (dict).

    Se semgrep non e' installato, solleva SemgrepNotAvailable: e'
    compito del chiamante (es. pipe.py) decidere se questo deve far
    fallire la fase o solo essere loggato e saltato (semgrep e'
    pensato come motore aggiuntivo, non come dipendenza obbligatoria).
    """
    _check_semgrep_available()

    input_path = Path(input_path)
    files = [input_path] if input_path.is_file() else sorted(input_path.rglob("*.c"))

    all_findings: list[dict] = []

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for f in files:
            print(f"[*] semgrep: analisi di {f.name} in corso...", flush=True)
            tmp_file = _prepend_ghidra_header(f, tmp_dir)
            raw_results = _run_semgrep_on_file(tmp_file, Path(rules_path))
            print(f"[*] semgrep: {f.name} completato ({len(raw_results)} match grezzi)", flush=True)
            line_to_func = _line_to_function(f.read_text(encoding="utf-8", errors="replace"))
            for r in raw_results:
                finding = _normalize_result(r, f.name)
                finding["function"] = line_to_func.get(finding["line"])
                all_findings.append(finding)

    output_json = Path(output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False), encoding="utf-8")

    return all_findings


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Semgrep scanner - Buffer Overflow (motore parallelo a YARA)")
    parser.add_argument("--input", required=True, help="File o cartella con pseudocodice Ghidra (.c)")
    parser.add_argument("--output", default="findings_semgrep.json", help="File JSON di output")
    args = parser.parse_args()

    findings = run_semgrep_scan(args.input, args.output)
    print(f"[+] {len(findings)} finding (semgrep) -> {args.output}")
    taint_hits = [f for f in findings if f["is_taint_rule"]]
    if taint_hits:
        print(f"[!] {len(taint_hits)} confermati dal taint tracking nativo di semgrep:")
        for f in taint_hits:
            print(f"    - {f['file']}:{f['line']} [{f['rule']}]")