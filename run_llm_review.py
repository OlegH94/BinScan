"""
run_llm_review.py
--------------------------------------------------------------------
Lancia llm_reviewer su tutti i binari gia' decompilati in risultati/
(o su uno solo con --only). Stesso pattern di rerun_scanning.py:
script standalone alla radice del progetto, non integrato in pipe.py
(llm_reviewer resta volutamente disaccoppiato — vedi
llm_reviewer/README.md).

Richiede Ollama in esecuzione in locale — se non e' raggiungibile,
lo script si ferma subito con un messaggio chiaro invece di fallire
silenziosamente binario per binario.

Uso:
    python run_llm_review.py
    python run_llm_review.py --only NOME_BIN
    python run_llm_review.py --model llama3.1:8b
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
from pathlib import Path

from pipe import RISULTATI_DIR, get_binary_paths
from llm_reviewer.llm_review import review_binary, OllamaNotAvailable, DEFAULT_MODEL


def _discover_processed_binaries(risultati_dir: Path) -> list[str]:
    return sorted(
        d.name for d in risultati_dir.iterdir()
        if d.is_dir() and (d / "decompiled_files").exists()
    )


def review_one(binary_name: str, risultati_dir: Path, model: str) -> dict:
    paths = get_binary_paths(binary_name, risultati_dir)
    decompiled_c = paths.decompiled_dir / f"{binary_name}_decompiled.c"
    findings_all = paths.vuln_scanner_dir / "findings_all.json"
    callgraph = paths.cfg_dir / "callgraph_named.graphml"
    output_dir = paths.root / "llm_review"

    if not decompiled_c.exists():
        print(f"[!] {binary_name}: nessuno pseudocodice decompilato trovato, salto")
        return {"binary": binary_name, "ok": False}

    print(f"\n{'=' * 70}\n[*] {binary_name}\n{'=' * 70}")

    entries = review_binary(
        decompiled_c,
        findings_all if findings_all.exists() else None,
        output_dir,
        model=model,
        callgraph_path=callgraph if callgraph.exists() else None,
    )

    n_vulnerable = sum(1 for e in entries if e.vulnerable)
    print(f"[+] {len(entries)} funzioni revisionate, {n_vulnerable} giudicate vulnerabili -> {output_dir}")

    return {"binary": binary_name, "ok": True, "reviewed": len(entries), "vulnerable": n_vulnerable}


def main() -> None:
    parser = argparse.ArgumentParser(description="Revisione LLM (Ollama locale) su tutto il batch")
    parser.add_argument("--only", metavar="NOME_BIN", default=None, help="Rilancia solo questo binario")
    parser.add_argument("--risultati-dir", default=str(RISULTATI_DIR), help="Cartella risultati/ (default: risultati)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Nome modello Ollama (default: {DEFAULT_MODEL})")
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)

    if args.only:
        binary_names = [args.only]
    else:
        binary_names = _discover_processed_binaries(risultati_dir)
        print(f"[*] {len(binary_names)} binari trovati in {risultati_dir}")

    results = []
    try:
        for binary_name in binary_names:
            results.append(review_one(binary_name, risultati_dir, args.model))
    except OllamaNotAvailable as e:
        print(f"\n[!] {e}")
        print("[!] Interrotto: Ollama non raggiungibile. Avvia Ollama e riprova.")
        return

    print(f"\n{'=' * 70}\n[*] RIEPILOGO\n{'=' * 70}")
    for r in results:
        status = "OK" if r["ok"] else "SALTATO"
        detail = f"{r.get('reviewed', 0)} revisionate, {r.get('vulnerable', 0)} vulnerabili" if r["ok"] else ""
        print(f"  {r['binary']:<60} [{status}]  {detail}")


if __name__ == "__main__":
    main()