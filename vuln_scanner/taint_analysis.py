"""
taint_analysis.py
--------------------------------------------------------------------
Taint analysis statica INTRAPROCEDURALE (per singola funzione), a
livello di riga, pensata per pseudocodice Ghidra.

Obiettivo (2.3 del progetto): una volta che lo scanner YARA ha
segnalato una funzione "debole" (es. usa memcpy/strcpy/sprintf...),
vogliamo sapere se l'input utente puo' davvero arrivarci: tracciamo
le variabili che ricevono dati da fonti non fidate (read, recv,
fgets, gets, scanf, getenv, argv, fread) e propaghiamo il tainting
attraverso assegnazioni semplici e chiamate a strcpy/memcpy/sprintf
che copiano una variabile taintata in un'altra. Se una variabile
taintata finisce come argomento in una delle chiamate sink flaggate
da YARA, il finding viene marcato come tainted=True con la sua
source.

Limiti dichiarati (da mettere in tesi):
- e' intraprocedurale: non segue il taint attraverso chiamate a
  funzioni custom (richiederebbe un vero data-flow interprocedurale,
  es. su CFG con angr) ne' puntatori/alias complessi;
- si basa su regex sulle righe di pseudocodice Ghidra, non su un AST;
  e' un'euristica volutamente semplice per restare nei tempi della
  tesi, non un taint tracker sound.
--------------------------------------------------------------------
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TAINT_SOURCES = [
    r"\bread\s*\(",
    r"\brecv\s*\(",
    r"\brecvfrom\s*\(",
    r"\bfgets\s*\(",
    r"\bgets\s*\(",
    r"\b(?:__isoc\d+_)?(?:scanf|fscanf)\s*\(",
    r"\bgetenv\s*\(",
    r"\bfread\s*\(",
    r"\bargv\s*\[",
]
_TAINT_SOURCE_RE = re.compile("|".join(TAINT_SOURCES))

# Chiamate che propagano il taint dal 2° argomento (src) al 1° (dest)
_PROPAGATORS = re.compile(
    r"\b(strcpy|strncpy|strcat|strncat|memcpy|memmove|sprintf|snprintf|vsprintf)\s*\("
)

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_SIMPLE_ASSIGN_RE = re.compile(rf"\b({_IDENT})\s*=\s*({_IDENT})\s*;")
_CALL_ARGS_RE = re.compile(rf"({_IDENT})\s*\((.*)\)")


def _extract_identifiers(fragment: str) -> set[str]:
    return set(re.findall(_IDENT, fragment))


@dataclass
class TaintResult:
    tainted: bool
    tainted_vars: set[str] = field(default_factory=set)
    source_lines: list[str] = field(default_factory=list)


def _split_args(args_str: str) -> list[str]:
    # split naive su virgola (sufficiente: lo pseudocodice Ghidra non
    # annida quasi mai chiamate con virgole dentro parentesi nei casi
    # che ci interessano; per i pochi che lo fanno il worst case e'
    # un argomento in piu' considerato, non una perdita di finding)
    return [a.strip() for a in args_str.split(",")]


def analyze_function_taint(function_text: str) -> dict[str, TaintResult]:
    """
    Esegue una passata line-by-line sulla funzione e restituisce, per
    ogni variabile che risulta taintata a fine analisi, un TaintResult
    con le righe sorgente che hanno introdotto/propagato il taint.

    Ritorna un dict {nome_variabile: TaintResult}. Le variabili non
    presenti nel dict sono considerate NON taintate.
    """
    tainted: dict[str, TaintResult] = {}
    lines = function_text.splitlines()

    for line in lines:
        # 1) nuove sorgenti di taint dirette: var = read(...)/fgets(buf, ...)/scanf("%s", &var)
        if _TAINT_SOURCE_RE.search(line):
            call_match = _CALL_ARGS_RE.search(line)
            candidate_vars: set[str] = set()

            # caso "var = func(...)" -> il lvalue e' taintato
            assign_lhs = re.match(rf"\s*({_IDENT})\s*=", line)
            if assign_lhs:
                candidate_vars.add(assign_lhs.group(1))

            # caso "func(buf, ...)" (es. fgets(buf, n, stdin), scanf("%s", &buf))
            # -> il/i buffer passati come argomento sono taintati
            if call_match:
                args = _split_args(call_match.group(2))
                for a in args:
                    ids = _extract_identifiers(a)
                    # scarta i nomi delle funzioni/costanti note, tieni identificatori "buffer-like"
                    candidate_vars |= {i for i in ids if i not in {"stdin", "stdout", "NULL"}}

            for v in candidate_vars:
                tr = tainted.setdefault(v, TaintResult(tainted=True))
                tr.source_lines.append(line.strip())
                tr.tainted_vars.add(v)

        # 2) propagazione tramite assegnazione semplice: dst = src;
        m = _SIMPLE_ASSIGN_RE.search(line)
        if m:
            dst, src = m.group(1), m.group(2)
            if src in tainted:
                tr = tainted.setdefault(dst, TaintResult(tainted=True))
                tr.source_lines.extend(tainted[src].source_lines)
                tr.tainted_vars.add(dst)

        # 3) propagazione tramite copy-call: strcpy(dst, src) / memcpy(dst, src, n) ecc.
        if _PROPAGATORS.search(line):
            call_match = _CALL_ARGS_RE.search(line)
            if call_match:
                args = _split_args(call_match.group(2))
                if len(args) >= 2:
                    dst_ids = _extract_identifiers(args[0])
                    src_ids = _extract_identifiers(args[1])
                    if any(s in tainted for s in src_ids):
                        source = next(s for s in src_ids if s in tainted)
                        for d in dst_ids:
                            tr = tainted.setdefault(d, TaintResult(tainted=True))
                            tr.source_lines.extend(tainted[source].source_lines)
                            tr.tainted_vars.add(d)

    return tainted


def sink_is_tainted(sink_line: str, tainted_vars: dict[str, TaintResult]) -> tuple[bool, list[str]]:
    """
    Data la riga del sink (il match YARA) e la mappa delle variabili
    taintate della funzione, dice se almeno un argomento del sink e'
    taintato, e restituisce le righe sorgente corrispondenti.
    """
    call_match = _CALL_ARGS_RE.search(sink_line)
    if not call_match:
        return False, []

    args_ids = _extract_identifiers(call_match.group(2))
    hit_sources: list[str] = []
    is_tainted = False

    for ident in args_ids:
        if ident in tainted_vars:
            is_tainted = True
            hit_sources.extend(tainted_vars[ident].source_lines)

    # dedup mantenendo l'ordine
    seen = set()
    unique_sources = []
    for s in hit_sources:
        if s not in seen:
            seen.add(s)
            unique_sources.append(s)

    return is_tainted, unique_sources
