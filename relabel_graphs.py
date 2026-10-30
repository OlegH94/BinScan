"""
relabel_graphs.py

Rietichetta i nodi "sub_XXXX" nei file GraphML prodotti da
angr_cfglib.py usando i nomi di funzione che Ghidra ha gia' risolto
via DWARF (il file *_symbols.json prodotto dalla versione aggiornata
di DecompScript.java).

Perche' serve: angr/cle non caricano i simboli DWARF delle vostre
funzioni utente, quindi angr_cfglib.py le chiama genericamente
"sub_<indirizzo>". Ghidra invece li ha gia' letti (li vedete nel log:
DWARFImportSummary) e li usa per il .c decompilato. Qui prendiamo in
prestito SOLO i nomi, non la struttura del grafo: il CFG/callgraph
restano quelli ricostruiti da angr (necessari per il resto della
pipeline: scanner vulnerabilita', seed fuzzing), solo con etichette
piu' leggibili.

Uso:
    python relabel_graphs.py target.exe_symbols.json callgraph.graphml -o callgraph_named.graphml
    python relabel_graphs.py target.exe_symbols.json cfg_global.graphml -o cfg_global_named.graphml
"""
import argparse
import json
import logging
import re

import networkx as nx

logging.basicConfig(level=logging.INFO, format="%(levelname)-8s | %(message)s")
logger = logging.getLogger("relabel_graphs")


def load_symbols(json_path: str) -> dict:
    """
    Carica la mappa indirizzo->nome prodotta da Ghidra e la normalizza
    a interi Python, cosi' e' direttamente confrontabile con gli id
    nodo (interi) usati nei GraphML di angr_cfglib.

    Gli indirizzi Ghidra a volte includono il nome dello spazio di
    indirizzamento (es. "ram:00401000"); viene rimosso in modo
    difensivo prima della conversione.
    """
    with open(json_path, "r") as f:
        raw = json.load(f)

    symbols = {}
    skipped = 0
    for addr_str, name in raw.items():
        hex_part = re.sub(r"^[a-zA-Z_]+:", "", addr_str)
        try:
            addr = int(hex_part, 16)
        except ValueError:
            skipped += 1
            continue
        symbols[addr] = name

    if skipped:
        logger.warning(f"{skipped} indirizzi nel JSON non sono stati riconosciuti e sono stati ignorati")

    return symbols


def relabel_callgraph(graphml_path: str, symbols: dict, output_path: str):
    """
    callgraph.graphml e' a livello di funzione: ogni nodo E' un
    indirizzo di funzione, quindi il match con i simboli Ghidra e'
    diretto e puo' coprire, in linea di principio, tutti i nodi.
    Il nome originale di angr (sub_XXXX o nome di libreria risolto
    dall'import table) viene conservato nell'attributo "angr_name",
    cosi' potete sempre confrontare/verificare.
    """
    G = nx.read_graphml(graphml_path)
    matched = 0

    for node_id, data in G.nodes(data=True):
        addr = int(node_id)
        if addr in symbols:
            data["angr_name"] = data.get("name", "")
            data["name"] = symbols[addr]
            matched += 1

    nx.write_graphml(G, output_path)
    logger.info(
        f"[callgraph] {matched}/{G.number_of_nodes()} nodi rietichettati -> {output_path}"
    )
    return matched, G.number_of_nodes()


def relabel_global_cfg(graphml_path: str, symbols: dict, output_path: str):
    """
    cfg_global.graphml e' a livello di basic block: SOLO i nodi che
    coincidono esattamente con l'indirizzo di ENTRY di una funzione
    (il primo blocco) possono essere rietichettati con un nome —
    i blocchi interni di una funzione restano senza nome. E' un
    limite intrinseco della granularita' del CFG globale, non un
    difetto di questo script: se vi serve vedere TUTTI i blocchi di
    una funzione con un'etichetta, usate invece il CFG per singola
    funzione (export_cfg(..., func_addr=...) in angr_cfglib.py) e
    rietichettatelo con la stessa logica.

    Il nome va in un attributo nuovo "function_name" per non entrare
    in conflitto con "size" gia' presente.
    """
    G = nx.read_graphml(graphml_path)
    matched = 0

    for node_id, data in G.nodes(data=True):
        addr = int(node_id)
        if addr in symbols:
            data["function_name"] = symbols[addr]
            matched += 1

    nx.write_graphml(G, output_path)
    logger.info(
        f"[cfg_global] {matched}/{G.number_of_nodes()} nodi di entry-point rietichettati "
        f"(gli altri sono blocchi interni, restano senza nome) -> {output_path}"
    )
    return matched, G.number_of_nodes()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rietichetta i grafi di angr_cfglib.py con i nomi risolti da Ghidra via DWARF"
    )
    parser.add_argument("symbols_json", help="File *_symbols.json prodotto da DecompScript.java")
    parser.add_argument("graphml", help="callgraph.graphml o cfg_global.graphml")
    parser.add_argument("-o", "--output", required=True, help="Path del file GraphML rietichettato")
    args = parser.parse_args()

    symbols = load_symbols(args.symbols_json)
    logger.info(f"Caricati {len(symbols)} simboli da {args.symbols_json}")

    name = args.graphml.lower()
    if "callgraph" in name:
        relabel_callgraph(args.graphml, symbols, args.output)
    elif "cfg_global" in name:
        relabel_global_cfg(args.graphml, symbols, args.output)
    else:
        logger.warning("Nome file non riconosciuto (ne' 'callgraph' ne' 'cfg_global'): uso relabel_callgraph di default")
        relabel_callgraph(args.graphml, symbols, args.output)