"""
visualize_callgraph.py

Script standalone per visualizzare SOLO il call graph (non il CFG
globale, che non e' pensato per l'ispezione visiva umana - vedi
angr_cfglib.py per il perche').

Usa un layout force-directed "sfdp" di Graphviz quando disponibile:
e' lo stesso algoritmo (Yifan Hu, multilevel force-directed) che
Gephi offre come layout "Yifan Hu" - i nodi isolati/debolmente
connessi vengono spinti ai bordi invece di restare ammassati al
centro, senza essere rimossi dal grafo.

Preferisce automaticamente callgraph_named.graphml (con i nomi
Ghidra) se presente nella stessa cartella, altrimenti usa
callgraph.graphml (nomi angr, sub_XXXX dove Ghidra non ha risolto).

Uso:
    python visualize_callgraph.py CFG/callgraph_named.graphml
    python visualize_callgraph.py CFG/callgraph.graphml -o out.png
"""
import argparse
import logging
import os

import matplotlib.pyplot as plt
import networkx as nx

logging.basicConfig(level=logging.INFO, format="%(levelname)-8s | %(message)s")
logger = logging.getLogger("visualize_callgraph")


def _sfdp_layout(G: nx.DiGraph):
    """
    Layout force-directed multilevel (algoritmo Yifan Hu) via Graphviz.
    Richiede pygraphviz o pydot + il binario 'sfdp' di Graphviz nel
    PATH di sistema. Se non disponibili, ripiega su spring_layout di
    networkx (visivamente piu' "compresso", ma senza dipendenze extra).
    """
    try:
        return nx.nx_agraph.graphviz_layout(G, prog="sfdp")
    except Exception:
        try:
            return nx.nx_pydot.graphviz_layout(G, prog="sfdp")
        except Exception:
            logger.warning(
                "sfdp (Graphviz/Yifan Hu) non disponibile: uso spring_layout. "
                "Per il layout identico a Gephi: pip install pygraphviz "
                "(richiede anche Graphviz di sistema - graphviz.org/download)."
            )
            return nx.spring_layout(G, seed=42, k=1.2, iterations=100)


def _node_label(G: nx.DiGraph, n) -> str:
    data = G.nodes[n]
    return data.get("name") or data.get("label") or f"0x{int(n):x}"


def visualize_callgraph(graphml_path: str, output_path: str = None,
                         figsize=(20, 16), label_min_degree: int = 1) -> str:
    """
    Args:
        graphml_path: path a callgraph.graphml o callgraph_named.graphml
        output_path: default: stesso nome, estensione .png
        label_min_degree: mostra l'etichetta solo per i nodi con
            grado totale (in+out) >= questa soglia, per non affollare
            il disegno di testo su centinaia di funzioni isolate.
            Mettete 0 per etichettare tutti i nodi.
    """
    G = nx.read_graphml(graphml_path)
    n_nodes, n_edges = G.number_of_nodes(), G.number_of_edges()
    logger.info(f"Call graph: {n_nodes} funzioni, {n_edges} chiamate")

    if n_nodes == 0:
        logger.warning("Grafo vuoto: nulla da disegnare.")
        return None

    pos = _sfdp_layout(G)

    in_deg = dict(G.in_degree())
    out_deg = dict(G.out_degree())
    total_deg = {n: in_deg.get(n, 0) + out_deg.get(n, 0) for n in G.nodes()}

    isolated = [n for n in G.nodes() if total_deg[n] == 0]
    roots = [n for n in G.nodes() if in_deg.get(n, 0) == 0 and out_deg.get(n, 0) > 0]
    normal = [n for n in G.nodes() if n not in isolated and n not in roots]

    plt.figure(figsize=figsize)

    # Isolate: piccole, grigie, sullo sfondo
    nx.draw_networkx_nodes(G, pos, nodelist=isolated, node_size=120,
                            node_color="#ced4da", alpha=0.6)
    # "Radici" (mai chiamate ma chiamano altro: candidate entry point/callback)
    nx.draw_networkx_nodes(G, pos, nodelist=roots, node_size=500,
                            node_color="#e03131", alpha=0.9)
    # Nodi normali, dimensionati per grado totale (gli hub piu' grandi)
    nx.draw_networkx_nodes(
        G, pos, nodelist=normal,
        node_size=[200 + total_deg[n] * 60 for n in normal],
        node_color="#4dabf7", alpha=0.85
    )

    nx.draw_networkx_edges(G, pos, arrows=True, arrowsize=8, alpha=0.35,
                            width=0.8, connectionstyle="arc3,rad=0.05")

    labels = {n: _node_label(G, n) for n in G.nodes() if total_deg[n] >= label_min_degree}
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)

    plt.title(
        f"Call Graph — {os.path.basename(graphml_path)}\n"
        f"{n_nodes} funzioni, {n_edges} chiamate  |  "
        f"blu = connesse, rosso = mai chiamate (radici), grigio = isolate ({len(isolated)})"
    )
    plt.axis("off")
    plt.tight_layout()

    output_path = output_path or graphml_path.replace(".graphml", ".png")
    plt.savefig(output_path, dpi=150)
    plt.close()
    logger.info(f"Salvato: {output_path}")
    return output_path


def _resolve_default_path(cfg_dir: str = "CFG") -> str:
    """Preferisce la versione rietichettata da Ghidra, se presente."""
    named = os.path.join(cfg_dir, "callgraph_named.graphml")
    plain = os.path.join(cfg_dir, "callgraph.graphml")
    if os.path.exists(named):
        return named
    return plain


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Visualizza il call graph con layout Yifan Hu / sfdp")
    parser.add_argument("path", nargs="?", default=None,
                         help="callgraph.graphml o callgraph_named.graphml "
                              "(default: cerca in CFG/, preferendo la versione _named)")
    parser.add_argument("--output", "-o", help="Path immagine di output")
    parser.add_argument("--label-min-degree", type=int, default=1,
                         help="Etichetta solo i nodi con grado >= N (default 1, cioe' niente etichette sugli isolati)")
    args = parser.parse_args()

    path = args.path or _resolve_default_path()
    if not os.path.exists(path):
        raise SystemExit(f"File non trovato: {path}")

    visualize_callgraph(path, args.output, label_min_degree=args.label_min_degree)