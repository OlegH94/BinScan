"""
claude_api_scanner.py
--------------------------------------------------------------------
Analizza lo pseudocodice decompilato (i binari Juliet, o un binario
reale come readelf) con l'API di Claude, usando OUTPUT STRUTTURATO
(tool use forzato, non testo libero) per ottenere un verdetto pulito
e facilmente confrontabile con la ground truth — a differenza di
VulnLLM-R, il cui output in testo libero si e' rivelato inaffidabile
da analizzare in modo automatico (Capitolo 6 di tesi).

Richiede una chiave API Anthropic nella variabile d'ambiente
ANTHROPIC_API_KEY.

Due modalita':
  --risultati-dir <cartella>   analizza TUTTI i binari li' dentro
                                (un file per binario, come i 142 Juliet)
  --single <file.c>            analizza UN SOLO file (es. readelf,
                                che grazie alla finestra di contesto
                                di Sonnet 5 (1M token) puo' stare
                                intero in una sola chiamata, senza
                                bisogno della segmentazione a blocchi
                                usata per VulnLLM-R)

Uso:
    python claude_api_scanner.py --risultati-dir risultati --model claude-haiku-4-5-20251001 --output claude_scan_results.json
    python claude_api_scanner.py --single risultati/readelf/decompiled_files/readelf_decompiled.c --model claude-sonnet-5 --output readelf_claude.json
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import anthropic

# Schema forzato per l'output: il modello DEVE restituire dati in
# questa forma esatta, non prosa libera — elimina il problema di
# parsing affrontato con VulnLLM-R (Capitolo 6).
VULNERABILITY_TOOL = {
    "name": "report_vulnerabilities",
    "description": "Riporta le vulnerabilita' individuate nel codice C decompilato fornito.",
    "input_schema": {
        "type": "object",
        "properties": {
            "accepts_external_input": {
                "type": "boolean",
                "description": (
                    "true se il programma legge dati da FUORI di se stesso in un punto "
                    "qualsiasi del codice mostrato (standard input, un file, un argomento "
                    "a riga di comando, una connessione di rete) — false se lavora solo su "
                    "dati che gia' esistono nel codice stesso (costanti, valori hardcoded)."
                ),
            },
            "vulnerable_functions": {
                "type": "array",
                "description": "Una voce per ogni funzione ritenuta vulnerabile. Vuoto se nessuna.",
                "items": {
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "Nome esatto della funzione, come appare nel codice (es. CWE121_..._bad)",
                        },
                        "cwe": {
                            "type": "string",
                            "description": "Identificativo CWE nel formato 'CWE-121'",
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["high", "medium", "low"],
                        },
                        "explanation": {
                            "type": "string",
                            "description": "Spiegazione breve (1-3 frasi) del problema e del flusso dati coinvolto",
                        },
                    },
                    "required": ["function_name", "cwe", "confidence", "explanation"],
                },
            },
        },
        "required": ["accepts_external_input", "vulnerable_functions"],
    },
}

SYSTEM_PROMPT = (
    "Sei un motore di analisi statica per la sicurezza del software. Ricevi pseudocodice "
    "C decompilato da Ghidra (nomi di variabili generici, tipi imprecisi come 'undefined4' "
    "sono normali, non indicano un problema). Prima di tutto, stabilisci se il programma "
    "legge dati da fuori di se stesso in un punto qualsiasi del codice mostrato (standard "
    "input, file, argomento a riga di comando, rete). Poi analizza il flusso dati tra le "
    "funzioni presenti e riporta OGNI funzione che contiene una vulnerabilita' reale "
    "(buffer overflow, lettura/scrittura fuori dai limiti, e simili), con la funzione "
    "esatta, la categoria CWE, una spiegazione breve, e un livello di confidenza. Se non "
    "trovi nulla, restituisci una lista vuota. Usa SEMPRE lo strumento fornito per "
    "rispondere, non aggiungere testo libero."
)


def _find_decompiled_c(binary_dir: Path) -> Path | None:
    decompiled_dir = binary_dir / "decompiled_files"
    if not decompiled_dir.is_dir():
        return None
    c_files = sorted(decompiled_dir.glob("*.c"))
    return c_files[0] if c_files else None


def analyze_file(client: anthropic.Anthropic, model: str, code: str, max_tokens: int = 4096) -> dict:
    """Una chiamata API, con output forzato tramite tool use. Ritorna il dict strutturato."""
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        tools=[VULNERABILITY_TOOL],
        tool_choice={"type": "tool", "name": "report_vulnerabilities"},
        messages=[{"role": "user", "content": f"Codice da analizzare:\n\n```c\n{code}\n```"}],
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "report_vulnerabilities":
            return block.input

    # Non dovrebbe succedere con tool_choice forzato, ma non si sa mai
    # con un servizio esterno — meglio un fallimento esplicito che un
    # crash silenzioso o un dato inventato.
    raise RuntimeError(f"Nessun tool_use trovato nella risposta: {response.content}")


def run_batch(risultati_dir: Path, model: str, client: anthropic.Anthropic) -> dict:
    binary_dirs = sorted(d for d in risultati_dir.iterdir() if d.is_dir())
    results = {}
    errors = []

    for i, d in enumerate(binary_dirs, 1):
        decompiled_c = _find_decompiled_c(d)
        if decompiled_c is None:
            continue

        code = decompiled_c.read_text(encoding="utf-8", errors="ignore")
        print(f"[*] [{i}/{len(binary_dirs)}] {d.name} ({len(code)} caratteri)...")

        try:
            verdict = analyze_file(client, model, code)
            results[d.name] = verdict
            n_vuln = len(verdict.get("vulnerable_functions", []))
            input_flag = "sì" if verdict.get("accepts_external_input") else "no"
            print(f"    -> input esterno: {input_flag} | {n_vuln} funzione/i segnalata/e")
        except Exception as e:
            print(f"    [!] ERRORE: {e}")
            errors.append(d.name)

        time.sleep(0.5)  # margine di cortesia contro i rate limit

    print(f"\n[+] {len(results)} binari analizzati, {len(errors)} errori")
    if errors:
        print(f"[!] Binari falliti: {', '.join(errors)}")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Analizza pseudocodice decompilato con l'API Claude, output strutturato")
    parser.add_argument("--risultati-dir", help="Analizza tutti i binari in questa cartella")
    parser.add_argument("--single", help="Analizza un solo file (es. readelf)")
    parser.add_argument("--model", default="claude-haiku-4-5-20251001",
                         help="Modello da usare (default: claude-haiku-4-5-20251001, il piu' economico)")
    parser.add_argument("--output", default="claude_scan_results.json")
    parser.add_argument("--max-tokens", type=int, default=4096,
                         help="Token massimi di output per chiamata (alza per file molto grandi come readelf)")
    args = parser.parse_args()

    if not args.risultati_dir and not args.single:
        print("[!] Serve --risultati-dir oppure --single")
        return

    client = anthropic.Anthropic()  # legge ANTHROPIC_API_KEY dall'ambiente

    if args.single:
        path = Path(args.single)
        if not path.exists():
            print(f"[!] {path} non trovato")
            return
        code = path.read_text(encoding="utf-8", errors="ignore")
        print(f"[*] Analizzo {path.name} ({len(code)} caratteri) con {args.model}...")
        verdict = analyze_file(client, args.model, code, max_tokens=args.max_tokens)
        results = {path.stem: verdict}
        n_vuln = len(verdict.get("vulnerable_functions", []))
        input_flag = "sì" if verdict.get("accepts_external_input") else "no"
        print(f"[+] Input esterno: {input_flag}")
        print(f"[+] {n_vuln} funzione/i segnalata/e:")
        for f in verdict.get("vulnerable_functions", []):
            print(f"    - {f['function_name']}: {f['cwe']} ({f['confidence']}) — {f['explanation']}")
    else:
        results = run_batch(Path(args.risultati_dir), args.model, client)

    Path(args.output).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Risultati scritti in: {args.output}")


if __name__ == "__main__":
    main()