#!/usr/bin/env python3
"""
angr CFG Analysis Library - FIXED
Libreria per l'analisi di Control Flow Graph con angr
Uso: from angr_cfglib import CFGAnalyzer
"""

import os
import json
import logging
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import networkx as nx
import angr

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class BasicBlockInfo:
    """Informazioni su un basic block"""
    addr: int
    size: int
    instructions: int
    predecessors: List[int]
    successors: List[int]
    entropy: float = 0.0


@dataclass
class FunctionAnalysis:
    """Risultato analisi di una funzione"""
    name: str
    addr: int
    blocks: int
    instructions: int
    cyclomatic_complexity: int
    number_of_loops: int
    number_of_calls: int
    is_recursive: bool
    has_unbounded_loop: bool
    basic_blocks: List[Tuple[int, int]]  # (addr, size)
    calls: List[Dict]
    loops: List[Dict]
    entry_block: int
    exit_blocks: List[int]


@dataclass
class Vulnerability:
    """Vulnerabilità rilevata"""
    vuln_type: str
    severity: str  # HIGH, MEDIUM, LOW
    func_name: str
    func_addr: int
    details: str
    score: float  # 0.0-1.0


# ============================================================================
# ANALIZZATORE CFG
# ============================================================================

class CFGAnalyzer:
    """
    Analizzatore di Control Flow Graph con angr

    Uso:
        analyzer = CFGAnalyzer("binary.exe")
        cfg = analyzer.get_cfg()
        func_analysis = analyzer.analyze_function(func_addr)
    """

    def __init__(self, binary_path: str, auto_load_libs: bool = False,
                 cfg_mode: str = "fast"):
        """
        Inizializza l'analizzatore

        Args:
            binary_path: Percorso del binary
            auto_load_libs: Se caricare librerie (default: False)
            cfg_mode: "fast" (CFGFast) o "accurate" (CFGAccurate)
        """

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary non trovato: {binary_path}")

        self.binary_path = binary_path
        self.cfg_mode = cfg_mode.lower()

        logger.info(f"Caricamento binary: {binary_path}")
        self.proj = angr.Project(binary_path, auto_load_libs=auto_load_libs)

        logger.info(f"Costruzione CFG ({self.cfg_mode})...")
        self._build_cfg()

        # Caching
        self._function_analyses = {}
        self._nx_graph = None

    def _build_cfg(self):
        """Costruisce il CFG"""
        try:
            if self.cfg_mode == "accurate":
                self.cfg = self.proj.analyses.CFGAccurate(
                    avoid_runs=True
                )
                logger.info("CFG Accurate costruito")
            else:
                self.cfg = self.proj.analyses.CFGFast(
                    normalize=True
                )
                logger.info("CFG Fast costruito")

            # FIX: list() prima di len() - su alcune combinazioni di
            # versioni angr/networkx, self.cfg.graph.nodes()/.edges()
            # restituiscono un generatore invece di una View con
            # supporto a len() diretto (TypeError: object of type
            # 'generator' has no len() - riprodotto e confermato).
            # list() funziona sempre, qualunque sia il tipo restituito.
            logger.info(f"CFG: {len(list(self.cfg.graph.nodes()))} nodi, "
                        f"{len(list(self.cfg.graph.edges()))} archi")

        except Exception as e:
            logger.error(f"Errore costruzione CFG: {e}")
            raise

    # ========================================================================
    # ACCESSO CFG
    # ========================================================================

    def get_cfg(self):
        """Restituisce l'oggetto CFG di angr"""
        return self.cfg

    def get_project(self):
        """Restituisce l'oggetto Project di angr"""
        return self.proj

    def get_functions(self) -> Dict[int, str]:
        """Restituisce dizionario {indirizzo: nome_funzione}"""
        return {
            addr: func.name
            for addr, func in self.proj.kb.functions.items()
        }

    def get_function_by_name(self, name: str) -> Optional[int]:
        """Trova indirizzo funzione per nome"""
        for addr, func in self.proj.kb.functions.items():
            if func.name == name:
                return addr
        return None

    def get_nx_graph(self) -> nx.DiGraph:
        """
        Converte CFG in NetworkX DiGraph
        Utile per analisi avanzate
        """
        if self._nx_graph is not None:
            return self._nx_graph

        logger.info("Conversione CFG in NetworkX...")
        G = nx.DiGraph()

        # FIX: Usa self.cfg.graph
        for node in self.cfg.graph.nodes():
            # alcuni CFGNode (es. blocchi syscall/PLT) possono avere
            # size=None: write_graphml puo' fallire su attributi None
            # FIX: networkx mappa sempre gli int Python su attr.type="long"
            # in GraphML, che alcune versioni di Gephi non importano
            # correttamente. Stringa = massima compatibilita' (Gephi la
            # converte comunque in numero se serve per dimensionare i nodi).
            G.add_node(node.addr, size=str(node.size or 0))

        for src, dst in self.cfg.graph.edges():
            G.add_edge(src.addr, dst.addr)

        self._nx_graph = G
        return G

    # ========================================================================
    # ANALISI FUNZIONI
    # ========================================================================

    def _safe_instruction_count(self, block) -> int:
        """
        Legge block.instructions in modo sicuro.

        block.instructions e' lazy: al primo accesso angr solleva (lift)
        i byte del blocco in IR VEX. Con CFGFast puo' capitare che un
        "basic block" scoperto euristicamente in realta' punti a dati,
        padding di allineamento o codice troncato: in quel caso il lift
        fallisce con SimTranslationError/PyVEXError. Non e' un bug nel
        nostro codice ma una normale imprecisione di CFGFast su binari
        reali, quindi va gestita per blocco invece di far cadere l'intera
        analisi della funzione (o dell'intero binario).
        """
        try:
            return block.instructions
        except Exception as e:
            logger.debug(
                f"Impossibile lift-are il blocco @ 0x{block.addr:x}: {e}"
            )
            return 0

    def analyze_function(self, func_addr: int) -> Optional[FunctionAnalysis]:
        """
        Analizza una funzione

        Args:
            func_addr: Indirizzo della funzione

        Returns:
            FunctionAnalysis o None se non trovata
        """
        # Cache
        if func_addr in self._function_analyses:
            return self._function_analyses[func_addr]

        func = self.proj.kb.functions.get(func_addr)
        if not func:
            logger.warning(f"Funzione @ 0x{func_addr:x} non trovata")
            return None

        logger.debug(f"Analisi funzione: {func.name} @ 0x{func_addr:x}")

        # FIX: func.blocks e' un generator in angr, non una lista.
        # Va materializzato una sola volta e riusato, altrimenti len()
        # fallisce (TypeError: object of type 'generator' has no len())
        # e ogni iterazione successiva lo ricalcolerebbe da zero.
        blocks_list = list(func.blocks)

        # Calcola metriche
        complexity = self._compute_cyclomatic_complexity(func, blocks_list)
        loops = self._find_loops_in_function(func, blocks_list)
        calls = self._extract_calls(func, blocks_list)
        is_recursive = self._is_recursive(func, calls)
        has_unbounded = self._has_unbounded_loop(func, blocks_list)

        analysis = FunctionAnalysis(
            name=func.name,
            addr=func_addr,
            blocks=len(blocks_list),
            # FIX: angr Block non ha attributo .insns (quello esiste solo
            # su block.capstone.insns). block.instructions e' gia' un intero
            # col conteggio delle istruzioni, non serve len().
            instructions=sum(self._safe_instruction_count(b) for b in blocks_list),
            cyclomatic_complexity=complexity,
            number_of_loops=len(loops),
            number_of_calls=len(calls),
            is_recursive=is_recursive,
            has_unbounded_loop=has_unbounded,
            basic_blocks=[(b.addr, b.size) for b in blocks_list],
            calls=calls,
            loops=loops,
            entry_block=func.addr,
            # FIX: angr Function non ha .return_blocks; l'attributo corretto
            # e' .ret_sites (i basic block che terminano con un return).
            # Per funzioni senza return (es. noreturn) e' semplicemente vuoto.
            exit_blocks=[b.addr for b in func.ret_sites]
        )

        self._function_analyses[func_addr] = analysis
        return analysis

    def analyze_all_functions(self) -> Dict[int, FunctionAnalysis]:
        """Analizza tutte le funzioni"""
        logger.info(f"Analisi di {len(self.proj.kb.functions)} funzioni...")

        analyses = {}
        for func_addr in self.proj.kb.functions:
            analysis = self.analyze_function(func_addr)
            if analysis:
                analyses[func_addr] = analysis

        return analyses

    def _compute_cyclomatic_complexity(self, func, blocks_list: Optional[List] = None) -> int:
        """
        Complessità ciclomatica = E - N + 2P
        E = archi, N = nodi, P = componenti connesse
        """
        try:
            # FIX: accetta la lista già materializzata da analyze_function;
            # se chiamato standalone, materializza qui (una sola volta)
            blocks_list = blocks_list if blocks_list is not None else list(func.blocks)
            subgraph_addrs = {b.addr for b in blocks_list}

            # Usa self.cfg.graph
            edges = sum(1 for src, dst in self.cfg.graph.edges()
                        if src.addr in subgraph_addrs and
                        dst.addr in subgraph_addrs)

            nodes = len(blocks_list)  # FIX: non più len(func.blocks) (generator)
            cyclomatic = max(edges - nodes + 2, 1)

            return cyclomatic
        except Exception as e:
            logger.debug(f"Errore calcolo complessità: {e}")
            return 1

    def _find_loops_in_function(self, func, blocks_list: Optional[List] = None) -> List[Dict]:
        """Identifica loop dentro una funzione"""
        loops = []
        blocks_list = blocks_list if blocks_list is not None else list(func.blocks)
        subgraph_addrs = {b.addr for b in blocks_list}

        try:
            # FIX: Usa self.cfg.graph
            for src, dst in self.cfg.graph.edges():
                if src.addr in subgraph_addrs and dst.addr in subgraph_addrs:
                    if dst.addr <= src.addr:  # Back-edge
                        loops.append({
                            "header": dst.addr,
                            "back_edge": src.addr
                        })
        except Exception as e:
            logger.debug(f"Errore rilevamento loop: {e}")

        return loops

    def _extract_calls(self, func, blocks_list: Optional[List] = None) -> List[Dict]:
        """
        Estrae le funzioni chiamate.

        FIX: la versione precedente usava insn.address (l'indirizzo
        dell'istruzione 'call' stessa) come "addr" della call, invece
        del reale target chiamato. Questo rompeva sia _is_recursive
        (confrontava call["addr"] con func.addr: quasi mai vero) sia
        get_call_graph (creava archi verso indirizzi di istruzioni
        interne invece che verso le funzioni chiamate — visibile nel
        callgraph.graphml con centinaia di nodi senza nome).
        Ora si usa l'API di angr (get_call_sites/get_call_target), che
        risolve il target reale anche per call dirette risolte dalla
        knowledge base.
        """
        calls = []

        try:
            for callsite in func.get_call_sites():
                target = func.get_call_target(callsite)
                if target is not None:
                    calls.append({
                        "callsite": callsite,
                        "addr": target,  # indirizzo della funzione chiamata
                    })
        except Exception as e:
            logger.debug(f"Errore estrazione calls: {e}")

        return calls

    def _is_recursive(self, func, calls: List[Dict]) -> bool:
        """Controlla se la funzione chiama se stessa"""
        for call in calls:
            if call["addr"] == func.addr:
                return True
        return False

    def _has_unbounded_loop(self, func, blocks_list: Optional[List] = None) -> bool:
        """Rilevamento euristico di loop infiniti"""
        loops = self._find_loops_in_function(func, blocks_list)
        return len(loops) > 0

    # ========================================================================
    # ANALISI AVANZATE
    # ========================================================================

    def get_call_graph(self) -> nx.DiGraph:
        """Costruisce il call graph globale"""
        logger.info("Costruzione call graph...")
        callgraph = nx.DiGraph()

        try:
            for func_addr, func in self.proj.kb.functions.items():
                callgraph.add_node(func_addr, name=func.name)
                calls = self._extract_calls(func)

                for call in calls:
                    # "addr" e' ora il target reale della call (fix in _extract_calls)
                    target = call.get("addr")
                    if target:
                        callgraph.add_edge(func_addr, target)

        except Exception as e:
            logger.warning(f"Errore costruzione call graph: {e}")

        return callgraph

    def get_callers(self, func_addr: int) -> List[int]:
        """Trova tutte le funzioni che chiamano questa funzione"""
        callgraph = self.get_call_graph()
        return list(callgraph.predecessors(func_addr))

    def get_callees(self, func_addr: int) -> List[int]:
        """Trova tutte le funzioni chiamate da questa funzione"""
        callgraph = self.get_call_graph()
        return list(callgraph.successors(func_addr))

    def get_function_metrics(self, func_addr: int) -> Dict:
        """Restituisce tutte le metriche di una funzione"""
        analysis = self.analyze_function(func_addr)
        if not analysis:
            return {}

        return {
            "name": analysis.name,
            "addr": hex(analysis.addr),
            "blocks": analysis.blocks,
            "instructions": analysis.instructions,
            "cyclomatic_complexity": analysis.cyclomatic_complexity,
            "number_of_loops": analysis.number_of_loops,
            "number_of_calls": analysis.number_of_calls,
            "is_recursive": analysis.is_recursive,
            "has_unbounded_loop": analysis.has_unbounded_loop,
            "entry_block": hex(analysis.entry_block),
            "exit_blocks": [hex(b) for b in analysis.exit_blocks]
        }

    def find_high_complexity_functions(self, threshold: int = 10) -> List[Tuple[int, int]]:
        """Trova funzioni con alta complessità ciclomatica"""
        logger.info(f"Ricerca funzioni con complessità > {threshold}...")

        complex_funcs = []
        for func_addr, analysis in self.analyze_all_functions().items():
            if analysis.cyclomatic_complexity >= threshold:
                complex_funcs.append((func_addr, analysis.cyclomatic_complexity))

        return sorted(complex_funcs, key=lambda x: x[1], reverse=True)

    # ========================================================================
    # RILEVAMENTO VULNERABILITÀ
    # ========================================================================

    def detect_vulnerabilities(self) -> List[Vulnerability]:
        """Rilevamento euristico di vulnerabilità"""
        logger.info("Rilevamento vulnerabilità...")

        vulnerabilities = []
        analyses = self.analyze_all_functions()

        for func_addr, analysis in analyses.items():

            # Euristica 1: Alta complessità ciclomatica
            if analysis.cyclomatic_complexity > 20:
                vuln = Vulnerability(
                    vuln_type="HIGH_COMPLEXITY",
                    severity="MEDIUM",
                    func_name=analysis.name,
                    func_addr=func_addr,
                    details=f"Cyclomatic complexity: {analysis.cyclomatic_complexity}",
                    score=min(0.3 + analysis.cyclomatic_complexity / 100, 0.8)
                )
                vulnerabilities.append(vuln)

            # Euristica 2: Loop potenzialmente infinito
            if analysis.has_unbounded_loop and analysis.number_of_loops > 0:
                vuln = Vulnerability(
                    vuln_type="UNBOUNDED_LOOP",
                    severity="HIGH",
                    func_name=analysis.name,
                    func_addr=func_addr,
                    details=f"Potential infinite loop ({analysis.number_of_loops} loops)",
                    score=0.7
                )
                vulnerabilities.append(vuln)

            # Euristica 3: Ricorsione (stack overflow)
            if analysis.is_recursive:
                vuln = Vulnerability(
                    vuln_type="RECURSIVE_FUNCTION",
                    severity="MEDIUM",
                    func_name=analysis.name,
                    func_addr=func_addr,
                    details="Recursive function - potential stack overflow",
                    score=0.5
                )
                vulnerabilities.append(vuln)

            # Euristica 4: Molte chiamate (code injection)
            if analysis.number_of_calls > 30:
                vuln = Vulnerability(
                    vuln_type="HIGH_CALL_COUNT",
                    severity="LOW",
                    func_name=analysis.name,
                    func_addr=func_addr,
                    details=f"High call count: {analysis.number_of_calls}",
                    score=0.3
                )
                vulnerabilities.append(vuln)

            # Euristica 5: Troppi basic blocks
            if analysis.blocks > 50:
                vuln = Vulnerability(
                    vuln_type="COMPLEX_FUNCTION",
                    severity="LOW",
                    func_name=analysis.name,
                    func_addr=func_addr,
                    details=f"Large number of basic blocks: {analysis.blocks}",
                    score=0.2
                )
                vulnerabilities.append(vuln)

        # Ordina per severity e score
        severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        vulnerabilities.sort(
            key=lambda x: (severity_order[x.severity], x.score),
            reverse=True
        )

        logger.info(f"Rilevate {len(vulnerabilities)} vulnerabilità")
        return vulnerabilities

    # ========================================================================
    # ESPORTAZIONE
    # ========================================================================

    def export_function_cfg_graphml(self, func_addr: int, output_path: str):
        """Esporta CFG di una funzione in GraphML"""
        func = self.proj.kb.functions.get(func_addr)
        if not func:
            logger.error(f"Funzione non trovata: 0x{func_addr:x}")
            return False

        try:
            G = nx.DiGraph()

            # Nodi
            for block in func.blocks:
                G.add_node(
                    block.addr,
                    label=f"0x{block.addr:x}",
                    size=str(block.size),
                    instructions=str(self._safe_instruction_count(block))  # FIX: str per compatibilita' Gephi (attr.type long) + lift puo' fallire su blocchi non validi
                )

            # Archi - FIX: Usa self.cfg.graph
            subgraph_addrs = {b.addr for b in func.blocks}
            for src, dst in self.cfg.graph.edges():
                if src.addr in subgraph_addrs and dst.addr in subgraph_addrs:
                    G.add_edge(src.addr, dst.addr)

            nx.write_graphml(G, output_path)
            logger.info(f"CFG esportato (GraphML): {output_path}")
            return True

        except Exception as e:
            logger.error(f"Errore esportazione GraphML: {e}")
            return False

    def export_function_cfg_dot(self, func_addr: int, output_path: str):
        """Esporta CFG di una funzione in DOT"""
        func = self.proj.kb.functions.get(func_addr)
        if not func:
            logger.error(f"Funzione non trovata: 0x{func_addr:x}")
            return False

        try:
            func_name = func.name or f"func_{func_addr:x}"

            dot_content = "digraph CFG {\n"
            dot_content += f'  label="Function: {func_name} @ 0x{func_addr:x}"\n'
            dot_content += '  rankdir=TB\n'

            # Nodi
            for block in func.blocks:
                dot_content += f'  node_{block.addr:x} '
                dot_content += f'[label="0x{block.addr:x}\\n{self._safe_instruction_count(block)} insn"];\n'

            # Archi - FIX: Usa self.cfg.graph
            subgraph_addrs = {b.addr for b in func.blocks}
            for src, dst in self.cfg.graph.edges():
                if src.addr in subgraph_addrs and dst.addr in subgraph_addrs:
                    dot_content += f'  node_{src.addr:x} -> node_{dst.addr:x};\n'

            dot_content += "}\n"

            with open(output_path, "w") as f:
                f.write(dot_content)

            logger.info(f"CFG esportato (DOT): {output_path}")
            logger.info(f"Genera PNG: dot -Tpng {output_path} -o {output_path}.png")
            return True

        except Exception as e:
            logger.error(f"Errore esportazione DOT: {e}")
            return False

    def export_global_cfg_graphml(self, output_path: str):
        """Esporta CFG globale in GraphML"""
        try:
            logger.info("Esportazione CFG globale (GraphML)...")
            G = self.get_nx_graph()
            nx.write_graphml(G, output_path)
            logger.info(f"CFG globale esportato: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Errore esportazione CFG globale: {e}")
            return False

    def export_call_graph_graphml(self, output_path: str):
        """Esporta call graph in GraphML"""
        try:
            logger.info("Esportazione call graph (GraphML)...")
            callgraph = self.get_call_graph()

            # Aggiungi attributi
            for node in callgraph.nodes():
                func = self.proj.kb.functions.get(node)
                if func:
                    callgraph.nodes[node]['name'] = func.name

            nx.write_graphml(callgraph, output_path)
            logger.info(f"Call graph esportato: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Errore esportazione call graph: {e}")
            return False

    def export_analysis_json(self, output_path: str):
        """Esporta analisi completa in JSON"""
        try:
            logger.info("Esportazione analisi (JSON)...")

            all_analyses = self.analyze_all_functions()
            vulns = self.detect_vulnerabilities()

            data = {
                "binary": self.binary_path,
                "cfg_mode": self.cfg_mode,
                "total_functions": len(all_analyses),
                "functions": {},
                "vulnerabilities": []
            }

            # Funzioni
            for func_addr, analysis in all_analyses.items():
                data["functions"][hex(func_addr)] = {
                    "name": analysis.name,
                    "blocks": analysis.blocks,
                    "instructions": analysis.instructions,
                    "cyclomatic_complexity": analysis.cyclomatic_complexity,
                    "loops": analysis.number_of_loops,
                    "calls": analysis.number_of_calls,
                    "recursive": analysis.is_recursive
                }

            # Vulnerabilità
            for vuln in vulns:
                data["vulnerabilities"].append({
                    "type": vuln.vuln_type,
                    "severity": vuln.severity,
                    "function": vuln.func_name,
                    "function_addr": hex(vuln.func_addr),
                    "details": vuln.details,
                    "score": vuln.score
                })

            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)

            logger.info(f"Analisi esportata: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Errore esportazione JSON: {e}")
            return False

    def export_report_txt(self, output_path: str):
        """Esporta report in testo"""
        try:
            logger.info("Esportazione report (TXT)...")

            with open(output_path, "w") as f:
                f.write("=" * 80 + "\n")
                f.write("CONTROL FLOW GRAPH ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n\n")

                f.write(f"Binary: {self.binary_path}\n")
                f.write(f"CFG Mode: {self.cfg_mode}\n")
                f.write(f"Entry Point: 0x{self.proj.entry:x}\n\n")

                # Statistiche globali
                f.write("GLOBAL STATISTICS\n")
                f.write("-" * 80 + "\n")
                f.write(f"Total Functions: {len(self.proj.kb.functions)}\n")
                # FIX: Usa self.cfg.graph, list() prima di len() per lo
                # stesso motivo del fix in _build_cfg (vedi commento li').
                f.write(f"Total Basic Blocks: {len(list(self.cfg.graph.nodes()))}\n")
                f.write(f"Total Edges: {len(list(self.cfg.graph.edges()))}\n\n")

                # Funzioni
                f.write("FUNCTIONS ANALYSIS\n")
                f.write("-" * 80 + "\n")

                all_analyses = self.analyze_all_functions()
                for func_addr in sorted(all_analyses.keys()):
                    analysis = all_analyses[func_addr]
                    f.write(f"\n{analysis.name} @ 0x{func_addr:x}\n")
                    f.write(f"  Blocks: {analysis.blocks}\n")
                    f.write(f"  Instructions: {analysis.instructions}\n")
                    f.write(f"  Cyclomatic Complexity: {analysis.cyclomatic_complexity}\n")
                    f.write(f"  Loops: {analysis.number_of_loops}\n")
                    f.write(f"  Calls: {analysis.number_of_calls}\n")
                    f.write(f"  Recursive: {analysis.is_recursive}\n")

                # Vulnerabilità
                f.write("\n\nVULNERABILITIES DETECTED\n")
                f.write("-" * 80 + "\n")

                vulns = self.detect_vulnerabilities()
                if not vulns:
                    f.write("No vulnerabilities detected\n")
                else:
                    for vuln in vulns:
                        f.write(f"\n[{vuln.severity}] {vuln.vuln_type}\n")
                        f.write(f"  Function: {vuln.func_name} @ 0x{vuln.func_addr:x}\n")
                        f.write(f"  Details: {vuln.details}\n")
                        f.write(f"  Score: {vuln.score:.2f}\n")

            logger.info(f"Report esportato: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Errore esportazione report: {e}")
            return False


# ============================================================================
# FUNZIONI DI UTILITÀ
# ============================================================================

def export_cfg(analyzer: CFGAnalyzer, output_dir: str,
               func_addr: Optional[int] = None):
    """
    Esporta tutti i formati CFG

    Args:
        analyzer: CFGAnalyzer
        output_dir: Directory output
        func_addr: Indirizzo funzione (None = tutto)
    """
    os.makedirs(output_dir, exist_ok=True)

    if func_addr:
        # Specifica funzione
        func = analyzer.proj.kb.functions.get(func_addr)
        if not func:
            logger.error(f"Funzione non trovata: 0x{func_addr:x}")
            return

        prefix = os.path.join(output_dir, f"cfg_{func_addr:x}")
        analyzer.export_function_cfg_graphml(func_addr, f"{prefix}.graphml")
        analyzer.export_function_cfg_dot(func_addr, f"{prefix}.dot")
    else:
        # Tutto
        analyzer.export_global_cfg_graphml(
            os.path.join(output_dir, "cfg_global.graphml")
        )
        analyzer.export_call_graph_graphml(
            os.path.join(output_dir, "callgraph.graphml")
        )
        analyzer.export_analysis_json(
            os.path.join(output_dir, "analysis.json")
        )
        analyzer.export_report_txt(
            os.path.join(output_dir, "report.txt")
        )


if __name__ == "__main__":
    # Test
    import sys

    if len(sys.argv) < 2:
        print("Uso: python angr_cfglib.py <binary> [output_dir]")
        sys.exit(1)

    binary = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "cfg_output"

    # Analizza
    analyzer = CFGAnalyzer(binary, cfg_mode="fast")

    # Esporta
    export_cfg(analyzer, output)

    # Mostra vulnerabilità
    vulns = analyzer.detect_vulnerabilities()
    print(f"\n[*] Vulnerabilità rilevate: {len(vulns)}")
    for vuln in vulns[:5]:  # Top 5
        print(f"  [{vuln.severity}] {vuln.vuln_type}: {vuln.func_name}")