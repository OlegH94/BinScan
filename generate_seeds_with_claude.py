"""
generate_seeds_with_claude.py
--------------------------------------------------------------------
Per ogni binario segnalato da claude_api_scanner.py come "accetta
input esterno", chiede a Claude di generare seed di fuzzing su misura
per quello specifico programma — invece dei seed generici basati su
pattern testuali di fuzz_seed_generator.py, pensati per input
semplici (stringhe/numeri via stdin) e inadeguati per formati
strutturati come un file ELF (il problema osservato su readelf,
Capitolo 6: zero crash in 15 minuti, seed generici mai vicini al
formato atteso).

Usa output strutturato (stessa tecnica di claude_api_scanner.py):
il modello descrive il formato di input atteso e propone un piccolo
insieme di seed, ciascuno con una motivazione (perche' e' un caso
interessante da testare — vicino a un limite di buffer, un valore di
edge case, ecc.).

I seed generati vengono scritti come file veri in una cartella
separata (fuzzing/seeds_claude/), MAI mescolati con quelli di
fuzz_seed_generator.py — cosi' si puo' fare un confronto diretto tra
i due approcci nella campagna di fuzzing, sullo stesso principio gia'
usato per "con seed" vs "senza seed".

Uso:
    python generate_seeds_with_claude.py --claude-results claude_scan_juliet.json --risultati-dir risultati_ablation_refined --model claude-haiku-4-5-20251001
    python generate_seeds_with_claude.py --single risultati/readelf/decompiled_files/readelf_decompiled.c --output-dir risultati/readelf/fuzzing/seeds_claude --model claude-sonnet-5
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import codecs
import json
from pathlib import Path

import anthropic

SEED_GENERATION_TOOL = {
    "name": "generate_seeds",
    "description": "Genera seed di fuzzing su misura per il programma analizzato.",
    "input_schema": {
        "type": "object",
        "properties": {
            "input_format_description": {
                "type": "string",
                "description": (
                    "Breve descrizione (1-2 frasi) di che tipo di input il programma si "
                    "aspetta e come lo legge (es. 'una stringa di testo letta da stdin con "
                    "fgets', 'un file ELF passato come primo argomento')."
                ),
            },
            "seeds": {
                "type": "array",
                "description": "3-6 seed distinti, pensati per esplorare casi limite diversi. OBBLIGATORIO: almeno 3 seed, anche se il programma sembra semplice.",
                "minItems": 3,
                "items": {
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": (
                                "Il contenuto del seed. Per input testuale, il testo stesso. "
                                "Per byte non stampabili o dati binari, usa escape stile "
                                "Python (\\xNN per un byte, \\n per newline, ecc.)."
                            ),
                        },
                        "rationale": {
                            "type": "string",
                            "description": "Perche' questo seed e' un caso interessante da testare",
                        },
                    },
                    "required": ["content", "rationale"],
                },
            },
        },
        "required": ["input_format_description", "seeds"],
    },
}

SYSTEM_PROMPT = (
    "Sei un esperto di fuzzing. Ricevi pseudocodice C decompilato da Ghidra di un programma "
    "che accetta input esterno (nomi di variabili generici e tipi imprecisi come 'undefined4' "
    "sono normali). Il tuo compito e' generare un piccolo insieme di SEED DI PARTENZA per una "
    "campagna di fuzzing — non input casuali, ma input scelti per essere strutturalmente validi "
    "secondo quello che il programma si aspetta, e per esplorare casi limite (dimensioni vicine "
    "o superiori a un buffer dichiarato, valori di bordo, formattazione minima valida per un "
    "eventuale parser). Usa SEMPRE lo strumento fornito per rispondere."
)


def _decode_seed_content(content: str) -> bytes:
    """Interpreta gli escape stile Python (\\xNN, \\n, ecc.) e ritorna i byte veri da scrivere su disco."""
    try:
        return codecs.escape_decode(content.encode("utf-8"))[0]
    except Exception:
        # se la decodifica fallisce, meglio scrivere il testo cosi' com'e'
        # che perdere il seed — un seed "sporco" e' comunque utile ad AFL++,
        # che muta comunque i byte di partenza.
        return content.encode("utf-8", errors="replace")


import re

# Due scorciatoie osservate empiricamente quando il modello scrive
# l'array come stringa (vedi sopra) invece che come vera struttura
# JSON: sintassi Python per stringhe ripetute ("A" * 100) e sequenze
# di escape esadecimali in stile Python/C (\xNN) — nessuna delle due
# e' JSON valido, e la seconda in particolare manda in errore
# l'intero array anche se il resto delle voci era corretto.
_PY_STRING_REPEAT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"\s*\*\s*(\d+)')
_PY_HEX_ESCAPE_RE = re.compile(r'\\x([0-9a-fA-F]{2})')


def _sanitize_python_string_repeat(text: str) -> str:
    def _expand(match: re.Match) -> str:
        content, count = match.group(1), int(match.group(2))
        return json.dumps(content * count)

    return _PY_STRING_REPEAT_RE.sub(_expand, text)


def _sanitize_hex_escapes(text: str) -> str:
    # \xNN (Python/C) -> \u00NN (JSON), stesso byte, sintassi diversa
    return _PY_HEX_ESCAPE_RE.sub(lambda m: "\\u00" + m.group(1), text)


def _as_list(raw) -> list:
    """Gestisce sia il caso normale (lista) sia la stranezza gia' osservata su
    claude_api_scanner.py: a volte il campo array torna come STRINGA
    contenente JSON invece che come vera lista (imperfezione isolata
    nell'aderenza allo schema forzato, non specifica di questo script).
    Prova anche a sanare due scorciatoie non-JSON osservate (ripetizione
    di stringa e escape esadecimali in stile Python) prima di arrendersi."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            pass
        try:
            sanitized = _sanitize_hex_escapes(_sanitize_python_string_repeat(raw))
            parsed = json.loads(sanitized)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def generate_seeds_for_code(client: anthropic.Anthropic, model: str, code: str) -> dict:
    response = client.messages.create(
        model=model,
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        tools=[SEED_GENERATION_TOOL],
        tool_choice={"type": "tool", "name": "generate_seeds"},
        messages=[{"role": "user", "content": f"Codice da analizzare:\n\n```c\n{code}\n```"}],
    )
    for block in response.content:
        if block.type == "tool_use" and block.name == "generate_seeds":
            return block.input
    raise RuntimeError(f"Nessun tool_use trovato nella risposta: {response.content}")


def write_seeds(seeds_result: dict, output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "input_format_description": seeds_result.get("input_format_description", ""),
        "seeds": [],
    }

    for i, seed in enumerate(_as_list(seeds_result.get("seeds"))):
        if not isinstance(seed, dict):
            print(f"    [!] Voce seed inattesa (tipo {type(seed).__name__}), saltata: {seed!r}")
            continue
        content_bytes = _decode_seed_content(seed.get("content", ""))
        seed_path = output_dir / f"claude_seed_{i:02d}"
        seed_path.write_bytes(content_bytes)
        manifest["seeds"].append({
            "file": seed_path.name,
            "rationale": seed.get("rationale", ""),
            "size_bytes": len(content_bytes),
        })

    # Stesso nome esatto ("manifest.json") gia' escluso da
    # _collect_real_seeds() in fuzzing_runner.py per i seed di
    # fuzz_seed_generator — necessario perche' quella funzione esclude
    # per NOME ESATTO, non per pattern: un nome diverso qui finirebbe
    # copiato nel corpus di seed e passato ad AFL++ come input vero,
    # contaminando l'esperimento.
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return len(manifest["seeds"])


def _find_decompiled_c(binary_dir: Path) -> Path | None:
    decompiled_dir = binary_dir / "decompiled_files"
    if not decompiled_dir.is_dir():
        return None
    c_files = sorted(decompiled_dir.glob("*.c"))
    return c_files[0] if c_files else None


def run_batch(claude_results_path: Path, risultati_dir: Path, model: str, client: anthropic.Anthropic) -> None:
    claude_results = json.loads(claude_results_path.read_text(encoding="utf-8"))

    eligible = [name for name, entry in claude_results.items() if entry.get("accepts_external_input")]
    print(f"[*] {len(eligible)} binari con input esterno (su {len(claude_results)} totali)")

    for i, binary_name in enumerate(eligible, 1):
        binary_dir = risultati_dir / binary_name
        decompiled_c = _find_decompiled_c(binary_dir)
        if decompiled_c is None:
            print(f"[!] [{i}/{len(eligible)}] {binary_name}: decompiled.c non trovato, salto")
            continue

        code = decompiled_c.read_text(encoding="utf-8", errors="ignore")
        print(f"[*] [{i}/{len(eligible)}] {binary_name}...")

        try:
            seeds_result = generate_seeds_for_code(client, model, code)
            output_dir = binary_dir / "fuzzing" / "seeds_claude"
            n = write_seeds(seeds_result, output_dir)
            print(f"    -> {n} seed scritti in {output_dir}")
            print(f"    -> formato riconosciuto: {seeds_result.get('input_format_description', '')}")
        except Exception as e:
            print(f"    [!] ERRORE: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera seed di fuzzing su misura con l'API Claude")
    parser.add_argument("--claude-results", help="File claude_scan_*.json da cui filtrare i binari con input esterno")
    parser.add_argument("--risultati-dir", default="risultati")
    parser.add_argument("--single", help="Analizza un solo file .c (es. readelf), ignora --claude-results")
    parser.add_argument("--output-dir", help="Cartella di output per --single (default: accanto al file, sottocartella seeds_claude)")
    parser.add_argument("--model", default="claude-haiku-4-5-20251001")
    args = parser.parse_args()

    client = anthropic.Anthropic()

    if args.single:
        path = Path(args.single)
        if not path.exists():
            print(f"[!] {path} non trovato")
            return
        code = path.read_text(encoding="utf-8", errors="ignore")
        print(f"[*] Genero seed per {path.name} con {args.model}...")
        seeds_result = generate_seeds_for_code(client, args.model, code)
        output_dir = Path(args.output_dir) if args.output_dir else path.parent / "seeds_claude"
        n = write_seeds(seeds_result, output_dir)
        print(f"[+] {n} seed scritti in {output_dir}")
        print(f"[+] Formato riconosciuto: {seeds_result.get('input_format_description', '')}")
        for s in _as_list(seeds_result.get("seeds")):
            if isinstance(s, dict):
                print(f"    - {s.get('rationale', '')}")
    elif args.claude_results:
        run_batch(Path(args.claude_results), Path(args.risultati_dir), args.model, client)
    else:
        print("[!] Serve --claude-results (batch) oppure --single (un file)")


if __name__ == "__main__":
    main()