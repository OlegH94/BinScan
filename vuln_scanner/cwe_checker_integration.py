"""
cwe_checker_integration.py
--------------------------------------------------------------------
Sostituto di BinAbsInspector: cwe_checker (Fraunhofer FKIE), motore
di abstract interpretation su Ghidra Pcode, ma attivamente mantenuto
(vs BinAbsInspector fermo al 2022) e distribuito come immagine Docker
pronta -> nessuna build da sorgente contro la propria versione di
Ghidra, nessun problema di compatibilita' JDK/Z3/Gradle.

Copre CWE-119 (Buffer Overflow) e le sue varianti CWE-125
(out-of-bounds read) e CWE-787 (out-of-bounds write). CWE-121
(Stack-Based Buffer Overflow, quello dei tuoi test case Juliet) e'
un CWE FIGLIO di CWE-119 nella tassonomia MITRE: cwe_checker non
riporta letteralmente "CWE121", riporta "CWE119"/"CWE787" — e' la
classificazione corretta a livello di parent, va solo tenuto
presente quando mappi/confronti i risultati con l'etichetta dei
tuoi test case Juliet nel Reporting Engine.

Uso:
    docker pull ghcr.io/fkie-cad/cwe_checker:stable   # una tantum

    from vuln_scanner.cwe_checker_integration import run_cwe_checker
    findings = run_cwe_checker(binary_path, output_json_path, symbols_json_path)
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

DOCKER_IMAGE = "ghcr.io/fkie-cad/cwe_checker:stable"

# CWE119 e' l'unico "modulo" selezionabile via --partial per il buffer
# overflow: CWE125 e CWE787, pur essendo CWE validi e citati nel
# README di cwe_checker come "varianti", NON sono moduli attivabili a
# se' stanti (--partial CWE787 fallisce con "not a valid module name",
# verificato sperimentalmente) — sono etichette che il check CWE119
# assegna ai singoli finding nel campo "name" a seconda del sottotipo
# rilevato (read fuori dai limiti -> CWE125, write fuori dai limiti
# -> CWE787). Il modulo CWE119 le produce comunque entrambe: non
# serve (e non si puo') richiederle separatamente.
BUFFER_OVERFLOW_CHECKS = ["CWE119"]


class CweCheckerNotAvailable(RuntimeError):
    """docker non è nel PATH, o l'immagine non è stata scaricata."""


def _check_docker_available() -> None:
    if shutil.which("docker") is None:
        raise CweCheckerNotAvailable(
            "docker non trovato nel PATH. Installa Docker Desktop e riprova."
        )


def _normalize_addr(addr: str) -> str:
    """
    Normalizza un indirizzo esadecimale per il confronto tra il
    formato di cwe_checker e quello di symbols.json (scritto da
    DecompScript.java come func.getEntryPoint().toString(false),
    cioe' hex puro senza prefisso "0x" e senza prefisso di spazio
    indirizzi tipo "ram:"). cwe_checker/Ghidra a volte prefissano
    con "ram:" o "0x": qui si toglie tutto cio' che non e' hex.
    """
    if not addr:
        return ""
    addr = addr.lower()
    addr = re.sub(r"^(0x|ram:)", "", addr)
    return addr.lstrip("0") or "0"


def _build_symbol_ranges(symbols_by_addr: dict[str, str]) -> list[tuple[int, str]]:
    """Converte {indirizzo_hex: nome} in una lista (indirizzo_intero, nome) ordinata per indirizzo."""
    pairs: list[tuple[int, str]] = []
    for addr_hex, name in symbols_by_addr.items():
        try:
            pairs.append((int(addr_hex, 16) if addr_hex else 0, name))
        except ValueError:
            continue
    pairs.sort(key=lambda p: p[0])
    return pairs


def _resolve_function_by_address(addr: str, sorted_symbols: list[tuple[int, str]]) -> str | None:
    """
    symbols.json contiene SOLO l'indirizzo di ENTRY POINT di ciascuna
    funzione, non ogni indirizzo al suo interno — un confronto a
    corrispondenza esatta contro quell'indirizzo fallisce quasi sempre,
    perche' cwe_checker riporta l'indirizzo dell'ISTRUZIONE specifica
    dove avviene il problema, che e' quasi sempre dentro il corpo della
    funzione, non al suo primo byte (bug reale osservato in produzione:
    un finding cwe_checker autentico veniva scartato con "function: None"
    e quindi ignorato sia da TP sia da FP nell'accuracy).

    Fix: troviamo l'ultima funzione il cui entry point e' <= all'indirizzo
    del finding — stesso principio gia' usato in
    juliet_ground_truth_importer.py per "riga -> funzione contenente",
    qui applicato a "indirizzo in un binario -> funzione contenente".
    Assume che le funzioni siano disposte in ordine di indirizzo senza
    grossi salti tra un corpo e l'altro — vero nella stragrande
    maggioranza dei binari compilati normalmente.
    """
    if not sorted_symbols:
        return None

    try:
        target = int(_normalize_addr(addr), 16) if addr else None
    except ValueError:
        return None
    if target is None:
        return None

    best_name = None
    for entry_addr, name in sorted_symbols:
        if entry_addr <= target:
            best_name = name
        else:
            break
    return best_name


def run_cwe_checker(
    binary_path: str | Path,
    output_json: str | Path,
    symbols_json: str | Path | None = None,
    checks: list[str] | None = BUFFER_OVERFLOW_CHECKS,
    docker_image: str = DOCKER_IMAGE,
) -> list[dict]:
    """
    Esegue cwe_checker su `binary_path` via Docker, normalizza
    l'output nello stesso "linguaggio" degli altri finding (function,
    cwe, description...) e lo scrive in `output_json`.

    Se `symbols_json` e' fornito (quello prodotto da
    decompiler.decompile(), stesso file passato a relabel_graphs.py),
    ogni warning con un indirizzo viene risolto al nome della
    funzione corrispondente — utile per incrociare i risultati con
    quelli di scanner.py/semgrep_scanner.py, che lavorano per nome
    funzione e non per indirizzo.

    Solleva CweCheckerNotAvailable se docker non e' disponibile: e'
    compito del chiamante (pipe.py) decidere se questo deve bloccare
    la fase o solo essere loggato e saltato.
    """
    _check_docker_available()

    binary_path = Path(binary_path).resolve()
    output_json = Path(output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)

    mount_dir = binary_path.parent
    container_binary = f"/input/{binary_path.name}"

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{mount_dir}:/input",
        docker_image,
        container_binary,
        "--json",
        "--quiet",
    ]
    if checks:
        cmd += ["--partial", ",".join(checks)]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] cwe_checker e' terminato con errore: {result.stderr[:1000]}")

    stdout = result.stdout.strip()
    if not stdout:
        print("[!] cwe_checker non ha prodotto output JSON")
        output_json.write_text("[]", encoding="utf-8")
        return []

    try:
        raw_warnings = json.loads(stdout)
    except json.JSONDecodeError:
        print("[!] Output di cwe_checker non e' JSON valido, controlla manualmente:")
        print(stdout[:2000])
        output_json.write_text("[]", encoding="utf-8")
        return []

    symbols_by_addr: dict[str, str] = {}
    if symbols_json:
        raw_symbols = json.loads(Path(symbols_json).read_text(encoding="utf-8"))
        symbols_by_addr = {_normalize_addr(k): v for k, v in raw_symbols.items()}
    sorted_symbols = _build_symbol_ranges(symbols_by_addr)

    findings = []
    for w in raw_warnings:
        addresses = w.get("addresses", [])
        resolved_function = None
        if addresses:
            resolved_function = _resolve_function_by_address(addresses[0], sorted_symbols)

        findings.append({
            "engine": "cwe_checker",
            "rule": w.get("name", ""),
            "description": w.get("description", ""),
            "cwe": w.get("name", ""),  # cwe_checker usa gia' "CWE119" ecc. come name
            "addresses": addresses,
            "function": resolved_function,  # None se non risolvibile: verifica simboli/formato indirizzo
        })

    output_json.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    return findings


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="cwe_checker wrapper - sostituto di BinAbsInspector")
    parser.add_argument("--binary", required=True, help="Path al binario da analizzare")
    parser.add_argument("--output", default="findings_cwe_checker.json")
    parser.add_argument("--symbols", default=None, help="Path a symbols.json (opzionale, per risolvere gli indirizzi a nomi funzione)")
    args = parser.parse_args()

    findings = run_cwe_checker(args.binary, args.output, args.symbols)
    print(f"[+] {len(findings)} finding (cwe_checker) -> {args.output}")
    for f in findings:
        func = f["function"] or f["addresses"]
        print(f"    [{f['cwe']}] {func}: {f['description'][:80]}")