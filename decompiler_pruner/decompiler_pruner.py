"""
decompiler_pruner.py
--------------------------------------------------------------------
Esporta una copia "pulita" e leggibile di un decompiled.c: solo
main() e tutte le funzioni transitivamente raggiungibili da esso,
escludendo stub di libreria e scaffolding di avvio/chiusura.

NON tocca il decompiled.c originale che il resto della pipeline
consuma (scanner.py, seed_generator.py, llm_reviewer) — produce un
file NUOVO, pensato per la lettura umana e per materiale di tesi, non
per essere ri-analizzato dagli altri componenti della pipeline.

Due modalita' di determinazione della raggiungibilita':

  1. CALL GRAPH REALE (preferita, se disponibile): usa
     CFG/callgraph_named.graphml (prodotto da angr_cfglib.py +
     relabel_graphs.py) — raggiungibilita' accurata anche in presenza
     di dispatch indiretto tramite puntatore a funzione, che angr
     risolve analizzando il binario, non il solo testo.

  2. FALLBACK TESTUALE (se il call graph non e' disponibile): cerca
     nel corpo di ogni funzione gia' inclusa occorrenze del nome di
     un'altra funzione definita nello stesso file, trattandole come
     chiamate. Euristica: puo' generare un falso positivo se il nome
     di una funzione compare anche come stringa letterale o commento
     nel corpo di un'altra (raro nello pseudocodice Ghidra), ma resta
     un'approssimazione ragionevole per un file pensato per la sola
     lettura, non per un'analisi automatica a valle.

Uso:
    python decompiler_pruner.py --input decompiled.c --output pulito.c
    python decompiler_pruner.py --input decompiled.c --output pulito.c --callgraph CFG/callgraph_named.graphml
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

_FUNC_SIGNATURE_RE = re.compile(r"^[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*\n\{", re.MULTILINE)

# Stessa lista e stesso controllo strutturale gia' applicati in
# vuln_scanner/scanner.py e fuzz_seed_generator/seed_generator.py —
# duplicati qui per tenere questa utility autosufficiente, coerente
# con la scelta gia' fatta altrove nel progetto per gli stessi motivi.
_KNOWN_LIBRARY_FUNCTIONS = {
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf", "gets", "fgets",
    "scanf", "sscanf", "fscanf",
    "__isoc99_scanf", "__isoc99_sscanf", "__isoc99_fscanf",
    "__isoc23_scanf", "__isoc23_sscanf", "__isoc23_fscanf", "__isoc23_swscanf",
    "printf", "fprintf", "read", "recv", "recvfrom", "fread", "alloca",
    "malloc", "calloc", "realloc", "free", "strlen", "strnlen", "getenv",
    "puts", "time", "srand", "rand", "exit", "abort",
    "wprintf", "iswxdigit", "__ctype_b_loc", "__cxa_finalize",
}
_STUB_CALL_RE = re.compile(r"\(\*\s*\(code\s*\*\)\s*PTR_")
_HALT_BADDATA_RE = re.compile(r"\bhalt_baddata\s*\(")


def _split_into_functions(source_text: str) -> dict[str, str]:
    """Ritorna {nome_funzione: corpo_completo}, escludendo stub/scaffolding esterni."""
    matches = list(_FUNC_SIGNATURE_RE.finditer(source_text))
    functions: dict[str, str] = {}
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source_text)
        name = m.group(1)
        body = source_text[start:end]

        if name in _KNOWN_LIBRARY_FUNCTIONS:
            continue
        if _STUB_CALL_RE.search(body) or _HALT_BADDATA_RE.search(body):
            continue

        # Se lo stesso nome compare piu' volte (raro, ma osservato per
        # duplicati non catturati dal filtro halt_baddata), tiene la
        # prima occorrenza — tipicamente la definizione "vera", le
        # successive sono di norma varianti rotte/incomplete.
        functions.setdefault(name, body)

    return functions


def _reachable_from_main_textual(functions: dict[str, str], entry: str = "main") -> set[str]:
    """
    Fallback testuale: BFS a partire da `entry`, seguendo ogni
    occorrenza (con confine di parola) del nome di un'altra funzione
    definita nello stesso file all'interno del corpo gia' incluso.
    """
    if entry not in functions:
        return set()

    reachable = {entry}
    to_visit = [entry]

    while to_visit:
        current = to_visit.pop()
        body = functions[current]
        for candidate_name in functions:
            if candidate_name in reachable:
                continue
            if re.search(rf"\b{re.escape(candidate_name)}\s*\(", body):
                reachable.add(candidate_name)
                to_visit.append(candidate_name)

    return reachable


def _reachable_from_main_callgraph(callgraph_path: Path, entry: str = "main") -> set[str] | None:
    """
    Usa CFG/callgraph_named.graphml se disponibile — stessa logica gia'
    usata in fuzz_seed_generator/seed_generator.py per la priorita'
    via raggiungibilita'. Ritorna None se il file non esiste o non e'
    leggibile, cosi' il chiamante puo' ricadere sul fallback testuale.
    """
    if not callgraph_path or not Path(callgraph_path).exists():
        return None

    try:
        import networkx as nx
        graph = nx.read_graphml(str(callgraph_path))
    except Exception:
        return None

    entry_node = None
    node_to_name = {}
    for node_id, data in graph.nodes(data=True):
        name = data.get("name")
        node_to_name[node_id] = name
        if name == entry:
            entry_node = node_id

    if entry_node is None:
        return None

    reachable = {entry}
    try:
        reachable.update(node_to_name[n] for n in nx.descendants(graph, entry_node) if node_to_name.get(n))
    except Exception:
        return None

    return reachable


def prune_decompiled(
    input_path: str | Path,
    output_path: str | Path,
    callgraph_path: str | Path | None = None,
    entry: str = "main",
) -> dict:
    """
    Ritorna un piccolo riepilogo (funzioni totali, tenute, modalita'
    di raggiungibilita' usata) oltre a scrivere il file di output.
    """
    source_text = Path(input_path).read_text(encoding="utf-8", errors="ignore")
    functions = _split_into_functions(source_text)

    reachable = _reachable_from_main_callgraph(Path(callgraph_path), entry) if callgraph_path else None
    mode = "callgraph"
    if reachable is None:
        reachable = _reachable_from_main_textual(functions, entry)
        mode = "testuale (fallback)"

    kept_names = [name for name in functions if name in reachable]

    header = (
        f"/* Copia pulita generata da decompiler_pruner.py — NON e' l'artefatto\n"
        f" * usato dal resto della pipeline (quello resta il decompiled.c\n"
        f" * originale). Mostra solo {entry}() e le funzioni raggiungibili da\n"
        f" * esso (modalita' di raggiungibilita': {mode}), per la lettura umana.\n"
        f" */\n\n"
    )
    body_text = "\n\n".join(functions[name].strip() for name in kept_names)

    Path(output_path).write_text(header + body_text + "\n", encoding="utf-8")

    return {
        "functions_total": len(functions),
        "functions_kept": len(kept_names),
        "kept_names": kept_names,
        "reachability_mode": mode,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Esporta una copia pulita di un decompiled.c (solo main + raggiungibili)")
    parser.add_argument("--input", required=True, help="File decompiled.c originale")
    parser.add_argument("--output", required=True, help="File di output (copia pulita)")
    parser.add_argument("--callgraph", default=None, help="CFG/callgraph_named.graphml opzionale, per raggiungibilita' reale")
    parser.add_argument("--entry", default="main", help="Funzione di ingresso da cui partire (default: main)")
    args = parser.parse_args()

    summary = prune_decompiled(args.input, args.output, args.callgraph, args.entry)
    print(f"[+] {summary['functions_total']} funzioni totali, {summary['functions_kept']} mantenute "
          f"(raggiungibilita': {summary['reachability_mode']})")
    print(f"[+] Copia pulita scritta in: {args.output}")
    for name in summary["kept_names"]:
        print(f"    - {name}")