"""
seed_generator.py
--------------------------------------------------------------------
Fuzzer Seed Generator (componente 2.4 della pipeline di tesi).

Genera un corpus di seed di partenza per una campagna di fuzzing
(AFL++, libFuzzer, o altro — il corpus prodotto e' agnostico rispetto
al fuzzer: e' solo una cartella di file), a partire da due fonti gia'
prodotte dalle fasi precedenti della pipeline:

  1. lo pseudocodice decompilato (decompiled_files/*.c) — per
     individuare le funzioni che accettano input esterno, riusando
     esattamente le stesse source pattern della taint analysis del
     vuln_scanner (vuln_scanner/taint_analysis.py): se una funzione e'
     una source per la taint analysis, e' per definizione anche un
     punto di ingresso rilevante per il fuzzing;
  2. i finding del vuln_scanner (findings_all.json) — per dare priorita'
     a seed dimensionati apposta per colpire i punti gia' identificati
     come vulnerabili (es. un buffer dichiarato di 15 byte con un
     overflow noto: generiamo seed di 14, 15, 16, 32... byte per
     quella specifica funzione);
  3. il call graph prodotto da angr_cfglib.py + relabel_graphs.py
     (CFG/callgraph_named.graphml) — qui e' dove entra davvero il
     "Code Coverage Guidance" dello spec: per ogni funzione vulnerabile
     trovata dal vuln_scanner, calcoliamo con networkx quali funzioni
     hanno un cammino di chiamata (diretto o transitivo) che arriva
     fino a li'. Una funzione di ingresso il cui cammino nel call
     graph raggiunge davvero il punto vulnerabile viene marcata
     "cfg_priority" e riceve piu' seed / una copia in seeds/_priority/;
     una funzione di ingresso che non ha alcun cammino verso codice
     vulnerabile noto resta comunque nel corpus (potrebbe raggiungere
     bug non ancora scoperti dal vuln_scanner), ma senza la priorita'.

Nota onesta sui limiti (da mettere in tesi): questo NON e' un vero
estrattore di formati/struct come uno strumento basato su grammatiche
o analisi simbolica — e' un generatore euristico basato su pattern
testuali sullo pseudocodice (dimensioni di buffer dichiarate, tipi di
sorgente di input, presenza di format string). Per target con formati
di file complessi (parser binari strutturati, protocolli con campi
dipendenti) andrebbe integrata un'estrazione piu' sofisticata — fuori
scope per ora, coerente con la scelta di concentrarsi sul buffer
overflow gia' fatta per il vuln_scanner.
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    from .taint_analysis import TAINT_SOURCES  # riusa il modulo vuln_scanner se presente nello stesso pacchetto
except ImportError:
    # fallback: import diretto se vuln_scanner e' una cartella sorella
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from vuln_scanner.taint_analysis import TAINT_SOURCES

_TAINT_SOURCE_RE = re.compile("|".join(TAINT_SOURCES))

# Sotto-pattern per distinguere il TIPO di ingresso (serve a scegliere
# la strategia di generazione: argv vs file vs stdin/rete vs scanf).
_ARGV_RE = re.compile(r"\bargv\s*\[")
_FILE_RE = re.compile(r"\b(fopen|fread)\s*\(")
_NET_RE = re.compile(r"\b(recv|recvfrom|read)\s*\(")

# Come in taint_analysis.py: il prefisso "__isocNN_" davanti a
# scanf/sscanf/fscanf e' opzionale, per coprire qualunque versione di
# glibc (__isoc99_scanf, __isoc23_fscanf, ecc.) invece di inseguire
# ogni singolo nome con un'aggiunta fissa in piu' — bug reale scoperto
# in produzione: un binario con __isoc23_fscanf dava sistematicamente
# zero funzioni di ingresso trovate, perche' "fscanf" da solo (con un
# \b prima) non riconosce mai "_fscanf" preceduto da un underscore
# (carattere di parola, quindi nessun vero confine di parola li').
_STDIN_SCANF_RE = re.compile(r"\b(?:__isoc\d+_)?(?:scanf|sscanf|fscanf)\s*\(|\bfgets\s*\(|\bgets\s*\(")

# Stessa regex del vuln_scanner per array a un byte per elemento
# (char/byte/undefined1...), per leggere le dimensioni dichiarate dei
# buffer nella stessa funzione di ingresso.
_BYTE_ARRAY_DECL_RE = re.compile(
    r"\b(?:undefined1|undefined|char|byte|uchar)\s+(\w+)\s*\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]"
)

# Firma di funzione, identica a quella di vuln_scanner/scanner.py — la
# duplico qui (invece di importarla) per tenere questo modulo
# utilizzabile anche senza vuln_scanner presente, dato che concettualmente
# la seed generation e' un consumer, non una dipendenza stretta del
# vulnerability scanner.
_FUNC_SIGNATURE_RE = re.compile(
    r"^[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*\n\{", re.MULTILINE
)

# Stesso identico problema gia' risolto in vuln_scanner/scanner.py:
# Ghidra scrive in cima al file i PROTOTIPI/wrapper delle funzioni di
# libreria esterne usate (es. un "wrapper" per read() stesso, che
# internamente richiama il puntatore PLT) — _split_into_functions() li
# riconosce come "funzioni" del programma a tutti gli effetti. Se il
# nome coincide con una nota funzione di libreria, il programma target
# non la definisce mai: va sempre escluso dalle funzioni di ingresso.
# Include ora anche le varianti __isoc99_/__isoc23_ di scanf/sscanf/
# fscanf, stesso motivo del fix sopra su _STDIN_SCANF_RE.
_KNOWN_LIBRARY_FUNCTIONS = {
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf", "gets", "fgets",
    "scanf", "sscanf", "fscanf",
    "__isoc99_scanf", "__isoc99_sscanf", "__isoc99_fscanf",
    "__isoc23_scanf", "__isoc23_sscanf", "__isoc23_fscanf",
    "printf", "fprintf", "read", "recv", "recvfrom", "fread", "alloca",
    "malloc", "calloc", "realloc", "free", "strlen", "strnlen", "getenv",
    "puts", "time", "srand", "rand", "exit", "abort",
}

# Controllo STRUTTURALE, complementare alla lista fissa sopra — stesso
# principio e stessa regex gia' applicati in vuln_scanner/scanner.py e
# in llm_reviewer/llm_review.py: funziona per QUALUNQUE stub esterno
# (anche scaffolding di avvio/chiusura come _start, register_tm_clones,
# mai contemplato nella lista fissa), non solo per i nomi gia' elencati.
_STUB_CALL_RE = re.compile(r"\(\*\s*\(code\s*\*\)\s*PTR_")
_HALT_BADDATA_RE = re.compile(r"\bhalt_baddata\s*\(")


def _parse_c_int(literal: str) -> int:
    return int(literal, 16) if literal.lower().startswith("0x") else int(literal)


def _split_into_functions(source_text: str) -> list[tuple[str, str]]:
    matches = list(_FUNC_SIGNATURE_RE.finditer(source_text))
    if not matches:
        return [("<intero_file>", source_text)]
    out = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source_text)
        name = m.group(1)
        body = source_text[start:end]
        if name in _KNOWN_LIBRARY_FUNCTIONS:
            continue
        if _STUB_CALL_RE.search(body) or _HALT_BADDATA_RE.search(body):
            continue
        out.append((name, body))
    return out


@dataclass
class InputFunction:
    function: str
    kind: str  # "argv" | "file" | "network" | "stdin_scanf" | "unknown"
    source_calls: list[str] = field(default_factory=list)
    declared_buffer_sizes: dict[str, int] = field(default_factory=dict)
    cfg_priority: bool = False  # True se il call graph mostra un cammino verso una funzione vulnerabile nota


def find_input_functions(decompiled_c_path: str | Path) -> list[InputFunction]:
    """
    Scansiona il file di pseudocodice e ritorna una InputFunction per
    ogni funzione che contiene almeno una chiamata a una source di
    taint (stesse pattern di vuln_scanner/taint_analysis.py — read,
    recv, fgets, scanf, argv, ecc.).
    """
    text = Path(decompiled_c_path).read_text(encoding="utf-8", errors="ignore")
    results: list[InputFunction] = []

    for func_name, func_text in _split_into_functions(text):
        source_calls = _TAINT_SOURCE_RE.findall(func_text)
        has_argv = bool(_ARGV_RE.search(func_text))
        if not source_calls and not has_argv:
            continue

        if has_argv:
            kind = "argv"
        elif _FILE_RE.search(func_text):
            kind = "file"
        elif _NET_RE.search(func_text):
            kind = "network"
        elif _STDIN_SCANF_RE.search(func_text):
            kind = "stdin_scanf"
        else:
            kind = "unknown"

        declared_sizes = {
            m.group(1): _parse_c_int(m.group(2))
            for m in _BYTE_ARRAY_DECL_RE.finditer(func_text)
        }

        results.append(
            InputFunction(
                function=func_name,
                kind=kind,
                source_calls=sorted(set(c for c in source_calls if c)),
                declared_buffer_sizes=declared_sizes,
            )
        )

    return results


# ---------------------------------------------------------------------
# Raggiungibilita' via call graph (CFG): qui usiamo davvero
# CFG/callgraph_named.graphml prodotto da angr_cfglib.py +
# relabel_graphs.py, non solo i finding. networkx e' gia' una
# dipendenza del progetto (usata da angr_cfglib.py e relabel_graphs.py
# per leggere/scrivere gli stessi file .graphml), quindi non serve
# installare nulla in piu'.
# ---------------------------------------------------------------------

def _vulnerable_functions_from_findings(findings_all_json: str | Path | None) -> set[str]:
    if not findings_all_json:
        return set()
    path = Path(findings_all_json)
    if not path.exists():
        return set()
    try:
        findings = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return {f["function"] for f in findings if f.get("function")}


def _load_callgraph(callgraph_graphml_path: str | Path):
    """
    Carica callgraph_named.graphml (o callgraph.graphml se il primo
    non e' disponibile, es. simboli Ghidra mancanti) e ritorna
    (grafo, {nome_funzione: node_id}). Ritorna (None, {}) se il file
    non esiste o non e' leggibile: la raggiungibilita' CFG e'
    un'ottimizzazione, non un requisito — il resto della generazione
    seed funziona comunque senza.
    """
    import networkx as nx  # gia' dipendenza del progetto (angr_cfglib.py, relabel_graphs.py)

    path = Path(callgraph_graphml_path)
    if not path.exists():
        return None, {}

    try:
        G = nx.read_graphml(str(path))
    except Exception as e:
        print(f"[!] Impossibile leggere il call graph {path}: {e}")
        return None, {}

    name_to_node: dict[str, str] = {}
    for node_id, data in G.nodes(data=True):
        name = data.get("name")
        if name:
            name_to_node.setdefault(name, node_id)

    return G, name_to_node


def _functions_reaching_targets(graph, name_to_node: dict[str, str], target_functions: set[str]) -> set[str]:
    """
    Per ogni funzione target (vulnerabile, dal vuln_scanner), calcola
    gli antenati nel call graph (tutte le funzioni che, direttamente
    o transitivamente, la chiamano) e ritorna l'unione dei loro nomi,
    incluse le funzioni target stesse (una funzione di ingresso PUO'
    essere gia' essa stessa la funzione vulnerabile).
    """
    import networkx as nx

    if graph is None:
        return set()

    reaching: set[str] = set()
    node_to_name = {n: d.get("name") for n, d in graph.nodes(data=True)}

    for func in target_functions:
        node = name_to_node.get(func)
        if node is None or node not in graph:
            continue
        reaching.add(func)
        try:
            ancestors = nx.ancestors(graph, node)
        except nx.NetworkXError:
            continue
        reaching.update(node_to_name[a] for a in ancestors if node_to_name.get(a))

    return reaching


def _target_sizes_from_findings(findings_all_json: str | Path | None, function: str) -> list[int]:
    """
    Legge findings_all.json (prodotto da pipe.py/vuln_scanner) e
    ritorna le dimensioni di buffer/size coinvolte nei finding di
    QUESTA specifica funzione, cosi' i seed possono essere costruiti
    apposta per colpire il punto gia' identificato come vulnerabile.
    """
    if not findings_all_json:
        return []

    path = Path(findings_all_json)
    if not path.exists():
        return []

    try:
        findings = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    sizes: set[int] = set()
    for f in findings:
        if f.get("function") != function:
            continue
        # BOF_Const_Size_Exceeds_Declared_Buffer mette la size copiata
        # nella description testuale ("copia N byte"); estraiamola.
        desc = f.get("description", "")
        m = re.search(r"copia (\d+) byte", desc)
        if m:
            sizes.add(int(m.group(1)))
    return sorted(sizes)


def _boundary_sizes(declared: int) -> list[int]:
    """Taglie 'interessanti' attorno a una dimensione dichiarata: appena sotto, esatta, appena sopra, doppia."""
    return sorted(set(s for s in (declared - 1, declared, declared + 1, declared * 2) if s > 0))


def generate_seeds_for_function(
    input_func: InputFunction,
    findings_all_json: str | Path | None = None,
) -> dict[str, bytes]:
    """
    Genera un piccolo set di seed (nome_file -> contenuto bytes) per
    UNA funzione di ingresso, combinando:
      - una taglia "baseline" ragionevole (16 byte stampabili)
      - le taglie di boundary di ogni buffer locale dichiarato nella
        stessa funzione (se ce ne sono)
      - le taglie estratte dai finding del vuln_scanner per quella
        funzione (la "guida" verso i punti gia' noti come vulnerabili)
      - per le funzioni scanf-style, un seed numerico oltre a uno
        testuale, dato che il formato atteso e' spesso ambiguo tra i due
      - se input_func.cfg_priority e' True (il call graph mostra un
        cammino verso una funzione vulnerabile nota), qualche taglia
        extra oltre alle boundary standard, per dare al fuzzer piu'
        varieta' di partenza proprio dove sappiamo che vale la pena
        insistere
    """
    seeds: dict[str, bytes] = {}

    seeds["baseline_16.bin"] = b"A" * 16

    target_sizes: set[int] = set()
    for declared in input_func.declared_buffer_sizes.values():
        target_sizes.update(_boundary_sizes(declared))
        if input_func.cfg_priority:
            target_sizes.update({declared * 3, declared * 4, declared + 8})
    target_sizes.update(_target_sizes_from_findings(findings_all_json, input_func.function))

    for size in sorted(target_sizes):
        seeds[f"size_{size:04d}.bin"] = b"A" * size

    if input_func.kind == "stdin_scanf":
        seeds["numeric.bin"] = b"12345\n"
        seeds["text.bin"] = b"AAAAAAAAAAAAAAAA\n"

    return seeds


@dataclass
class SeedGenerationSummary:
    input_functions_found: int
    seeds_written: int
    per_function: dict[str, int] = field(default_factory=dict)
    cfg_priority_functions: list[str] = field(default_factory=list)


def generate_seed_corpus(
    decompiled_c_path: str | Path,
    output_dir: str | Path,
    findings_all_json: str | Path | None = None,
    callgraph_graphml_path: str | Path | None = None,
) -> SeedGenerationSummary:
    """
    Entry point pensato per essere chiamato da pipe.py. Scrive i seed
    in output_dir/<nome_funzione>/<file_seed>, una copia dei seed delle
    funzioni "cfg_priority" in output_dir/_priority/ (comodo per
    puntare li' una prima passata di AFL++ prima di allargare a tutto
    il corpus), e un manifest.json con la provenienza di ogni seed.

    Se callgraph_graphml_path e' None o il file non esiste, la
    raggiungibilita' CFG viene semplicemente saltata (nessuna funzione
    marcata prioritaria) — resta un'ottimizzazione, non un requisito:
    il corpus base si genera comunque.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    input_functions = find_input_functions(decompiled_c_path)

    # Raggiungibilita' via call graph: quali funzioni di ingresso
    # hanno un cammino di chiamata verso una funzione gia' segnalata
    # come vulnerabile dal vuln_scanner.
    if callgraph_graphml_path:
        vulnerable_functions = _vulnerable_functions_from_findings(findings_all_json)
        graph, name_to_node = _load_callgraph(callgraph_graphml_path)
        reaching = _functions_reaching_targets(graph, name_to_node, vulnerable_functions)
        for input_func in input_functions:
            input_func.cfg_priority = input_func.function in reaching

    manifest: list[dict] = []
    per_function_counts: dict[str, int] = {}
    priority_dir = output_dir / "_priority"

    for input_func in input_functions:
        func_dir = output_dir / input_func.function
        func_dir.mkdir(parents=True, exist_ok=True)

        seeds = generate_seeds_for_function(input_func, findings_all_json)
        for filename, content in seeds.items():
            (func_dir / filename).write_bytes(content)
            manifest.append({
                "function": input_func.function,
                "kind": input_func.kind,
                "source_calls": input_func.source_calls,
                "cfg_priority": input_func.cfg_priority,
                "file": str((func_dir / filename).relative_to(output_dir)),
                "size": len(content),
            })

            if input_func.cfg_priority:
                priority_dir.mkdir(parents=True, exist_ok=True)
                (priority_dir / f"{input_func.function}__{filename}").write_bytes(content)

        per_function_counts[input_func.function] = len(seeds)

    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    return SeedGenerationSummary(
        input_functions_found=len(input_functions),
        seeds_written=len(manifest),
        per_function=per_function_counts,
        cfg_priority_functions=sorted(f.function for f in input_functions if f.cfg_priority),
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fuzzer Seed Generator")
    parser.add_argument("--input", required=True, help="File di pseudocodice decompilato (.c)")
    parser.add_argument("--output", required=True, help="Cartella di output per il corpus di seed")
    parser.add_argument("--findings", default=None, help="Path a findings_all.json (opzionale, per guidare le taglie)")
    parser.add_argument("--callgraph", default=None, help="Path a CFG/callgraph_named.graphml (opzionale, per la priorita' via raggiungibilita')")
    args = parser.parse_args()

    summary = generate_seed_corpus(args.input, args.output, args.findings, args.callgraph)
    print(f"[+] Funzioni di ingresso trovate: {summary.input_functions_found}")
    print(f"[+] Seed scritti: {summary.seeds_written}")
    for func, count in summary.per_function.items():
        print(f"    - {func}: {count} seed")
    if summary.cfg_priority_functions:
        print(f"[!] Funzioni prioritarie (call graph -> codice vulnerabile noto): {', '.join(summary.cfg_priority_functions)}")
    if summary.input_functions_found == 0:
        print("[!] Nessuna funzione con input esterno individuata: "
              "se il binario non legge da file/stdin/rete/argv (es. usa solo dati "
              "hardcoded), questo e' il risultato atteso, non un errore.")