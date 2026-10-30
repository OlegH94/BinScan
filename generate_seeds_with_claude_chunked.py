"""
generate_seeds_with_claude_chunked.py
--------------------------------------------------------------------
Variante di generate_seeds_with_claude.py per file troppo grandi
anche per la finestra di contesto del modello scelto (stesso limite
incontrato con claude_api_scanner_chunked.py: readelf supera anche i
200K token di Haiku).

Genera seed per OGNI blocco (stessa segmentazione per confini di
funzione di claude_api_scanner_chunked.py), poi unisce tutti i seed
in un'unica cartella — non un seed "ottimale unico", ma un insieme
più ricco che copre la comprensione del modello su diverse porzioni
del programma (per un formato di file come ELF, dove il parsing
dell'header e delle sezioni e' sparso su piu' funzioni, prendere un
solo blocco isolato rischierebbe di perdere il contesto sul formato
nel suo insieme).

Uso:
    python generate_seeds_with_claude_chunked.py --input risultati\\readelf\\decompiled_files\\readelf_decompiled.c --output-dir risultati\\readelf\\fuzzing\\seeds_claude --model claude-haiku-4-5-20251001
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import anthropic

from claude_api_scanner_chunked import split_by_function_boundary
from generate_seeds_with_claude import (
    SEED_GENERATION_TOOL,
    SYSTEM_PROMPT,
    _as_list,
    _decode_seed_content,
)


def generate_seeds_for_chunk(client: anthropic.Anthropic, model: str, code: str, max_tokens: int) -> dict:
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        tools=[SEED_GENERATION_TOOL],
        tool_choice={"type": "tool", "name": "generate_seeds"},
        messages=[{"role": "user", "content": f"Codice da analizzare:\n\n```c\n{code}\n```"}],
    )
    for block in response.content:
        if block.type == "tool_use" and block.name == "generate_seeds":
            return block.input
    raise RuntimeError(f"Nessun tool_use trovato nella risposta: {response.content}")


def write_merged_seeds(all_seeds: list[dict], descriptions: list[str], output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "input_format_description": " | ".join(d for d in descriptions if d),
        "seeds": [],
    }

    for i, seed in enumerate(all_seeds):
        content_bytes = _decode_seed_content(seed.get("content", ""))
        seed_path = output_dir / f"claude_seed_{i:02d}"
        seed_path.write_bytes(content_bytes)
        manifest["seeds"].append({
            "file": seed_path.name,
            "rationale": seed.get("rationale", ""),
            "size_bytes": len(content_bytes),
        })

    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return len(manifest["seeds"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera seed a blocchi, per file troppo grandi per il contesto del modello")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--model", default="claude-haiku-4-5-20251001")
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument(
        "--max-chars-per-chunk", type=int, default=350_000,
        help="Default calibrato per Haiku 4.5 (200K token) — alzare fino a ~1.000.000 con Sonnet 5 (1M token).",
    )
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        print(f"[!] {path} non trovato")
        return

    code = path.read_text(encoding="utf-8", errors="ignore")
    print(f"[*] {path.name}: {len(code)} caratteri")

    chunks = split_by_function_boundary(code, args.max_chars_per_chunk)
    print(f"[*] File diviso in {len(chunks)} blocchi")

    client = anthropic.Anthropic()

    all_seeds: list[dict] = []
    descriptions: list[str] = []

    for i, chunk in enumerate(chunks, 1):
        header = (
            f"/* NOTA: questo e' il blocco {i} di {len(chunks)} di un programma piu' grande. "
            f"Stai vedendo solo questa porzione del codice. Se non vedi una funzione che legge "
            f"input dall'esterno in questo blocco, restituisci comunque almeno 3 seed generici "
            f"plausibili per il formato che riconosci (es. struttura dati vista nelle firme di "
            f"funzione), motivando la tua incertezza nella spiegazione. */\n\n"
        )
        print(f"[*] Blocco {i}/{len(chunks)} ({len(chunk)} caratteri)...")

        try:
            result = generate_seeds_for_chunk(client, args.model, header + chunk, args.max_tokens)
        except Exception as e:
            print(f"    [!] ERRORE: {e}")
            continue

        seeds = [s for s in _as_list(result.get("seeds")) if isinstance(s, dict)]
        all_seeds.extend(seeds)
        descriptions.append(result.get("input_format_description", ""))
        print(f"    -> {len(seeds)} seed generati in questo blocco")

    output_dir = Path(args.output_dir)
    n = write_merged_seeds(all_seeds, descriptions, output_dir)

    print(f"\n[+] {n} seed totali (da {len(chunks)} blocchi) scritti in: {output_dir}")


if __name__ == "__main__":
    main()