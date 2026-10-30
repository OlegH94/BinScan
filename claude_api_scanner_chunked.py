"""
claude_api_scanner_chunked.py
--------------------------------------------------------------------
Variante di claude_api_scanner.py per file troppo grandi anche per
la finestra di contesto da 1M token di Sonnet 5 (caso reale: readelf,
2.680.681 caratteri = 1.323.224 token — supera il limite anche con
Sonnet, servono comunque dei blocchi, ma MOLTO piu' grandi e MOLTO
meno numerosi di quelli usati per VulnLLM-R (2-3 contro 41), grazie
alla finestra di contesto enormemente piu' ampia).

Divide il file per confini di funzione (mai spezza una funzione a
meta'), con un limite di caratteri per blocco calibrato per restare
ben sotto il milione di token (rapporto osservato empiricamente su
questo stesso file: ~2 caratteri per token, non i ~3,5 stimati in
precedenza per VulnLLM-R — modelli diversi tokenizzano diversamente).

Ogni blocco riceve un'intestazione che avvisa il modello di vedere
solo una porzione del file, sullo stesso principio gia' usato per
VulnLLM-R (Capitolo 6) — con la differenza che qui il numero di
blocchi e' cosi' piccolo che la perdita di contesto interprocedurale
tra un blocco e l'altro e' un rischio molto minore.

Uso:
    python claude_api_scanner_chunked.py --input risultati\\readelf\\decompiled_files\\readelf_decompiled.c --model claude-sonnet-5 --output claude_scan_readelf.json
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import anthropic

from claude_api_scanner import VULNERABILITY_TOOL, analyze_file

# Stesso rapporto caratteri/byte del resto del progetto (split_large_file.py,
# vuln_scanner/scanner.py) per riconoscere i confini di funzione senza
# mai spezzarne una a meta'.
_FUNC_SIGNATURE_RE = re.compile(r'^[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*\n\{', re.MULTILINE)

# Il valore di default e' impostato sul parametro --max-chars-per-chunk
# (vedi main()), calibrato sulla finestra di contesto piu' piccola tra
# i modelli usati in questo progetto — niente piu' costante fissa qui,
# dato che il limite vero dipende dal MODELLO scelto, non dal file.


def split_by_function_boundary(source_text: str, max_chars: int) -> list[str]:
    matches = list(_FUNC_SIGNATURE_RE.finditer(source_text))
    if not matches:
        return [source_text]

    chunks = []
    current_start = 0
    current_size = 0

    boundaries = [m.start() for m in matches] + [len(source_text)]

    for i in range(len(boundaries) - 1):
        func_size = boundaries[i + 1] - boundaries[i]
        if current_size + func_size > max_chars and current_size > 0:
            chunks.append(source_text[current_start:boundaries[i]])
            current_start = boundaries[i]
            current_size = 0
        current_size += func_size

    chunks.append(source_text[current_start:])
    return chunks


def analyze_chunked(client: anthropic.Anthropic, model: str, code: str, max_tokens: int, max_chars_per_chunk: int) -> dict:
    chunks = split_by_function_boundary(code, max_chars_per_chunk)
    print(f"[*] File diviso in {len(chunks)} blocchi (per confini di funzione)")

    merged = {"accepts_external_input": False, "vulnerable_functions": []}

    for i, chunk in enumerate(chunks, 1):
        header = (
            f"/* NOTA: questo e' il blocco {i} di {len(chunks)} di un programma piu' grande. "
            f"Stai vedendo solo questa porzione del codice, non il file intero. "
            f"Analizza solo quello che vedi qui. */\n\n"
        )
        print(f"[*] Blocco {i}/{len(chunks)} ({len(chunk)} caratteri)...")

        verdict = analyze_file(client, model, header + chunk, max_tokens=max_tokens)

        if verdict.get("accepts_external_input"):
            merged["accepts_external_input"] = True

        vulnerable_functions = verdict.get("vulnerable_functions", [])
        if isinstance(vulnerable_functions, str):
            try:
                vulnerable_functions = json.loads(vulnerable_functions)
            except json.JSONDecodeError:
                vulnerable_functions = []
        if isinstance(vulnerable_functions, list):
            merged["vulnerable_functions"].extend(vulnerable_functions)

        n_vuln = len(vulnerable_functions) if isinstance(vulnerable_functions, list) else 0
        print(f"    -> {n_vuln} funzione/i segnalata/e in questo blocco")

    return merged


def main() -> None:
    parser = argparse.ArgumentParser(description="Analizza con Claude un file troppo grande anche per la finestra di contesto, a blocchi")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model", default="claude-sonnet-5")
    parser.add_argument("--output", default="claude_scan_chunked.json")
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument(
        "--max-chars-per-chunk", type=int, default=350_000,
        help=(
            "Default calibrato per la finestra di contesto PIU' PICCOLA tra i modelli "
            "usati in questo progetto (Haiku 4.5, 200K token) — con Sonnet 5 (1M token) "
            "si puo' alzare fino a circa 1.000.000 per usare meno chiamate."
        ),
    )
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        print(f"[!] {path} non trovato")
        return

    code = path.read_text(encoding="utf-8", errors="ignore")
    print(f"[*] {path.name}: {len(code)} caratteri")

    client = anthropic.Anthropic()
    result = analyze_chunked(client, args.model, code, args.max_tokens, args.max_chars_per_chunk)

    output = {path.stem: result}
    Path(args.output).write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    n_total = len(result["vulnerable_functions"])
    print(f"\n[+] Totale: {n_total} funzione/i segnalata/e su tutti i blocchi")
    print(f"[+] Input esterno: {result['accepts_external_input']}")
    print(f"[+] Scritto in: {args.output}")


if __name__ == "__main__":
    main()