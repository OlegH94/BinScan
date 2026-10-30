"""
context_analyzer.py
--------------------------------------------------------------------
YARA individua i CANDIDATI (chiamate/pattern pericolosi) ma non puo'
valutare condizioni semantiche come "manca un controllo di dimensione
a monte" (il `condition: "no_size_check(dest, src)"` dell'esempio del
professore e' pseudocodice, non sintassi YARA valida).

Questo modulo prende in input la funzione (stringa di pseudocodice)
e l'offset del match YARA al suo interno, e cerca nelle righe
circostanti indizi di un controllo di dimensione gia' presente
(sizeof, strlen confrontata con una costante, un if con < o <= su una
variabile di lunghezza, uso di snprintf/strncpy/strncat, ecc.).

Non e' un dataflow reale: e' un'euristica per finestra di righe,
sufficiente per lo scopo dichiarato (ridurre falsi positivi grossolani
senza scartare mai un match: ogni finding resta nell'output ma con un
flag `context_checked` + un `confidence` diverso).
--------------------------------------------------------------------
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Pattern che, se trovati vicino al match, suggeriscono che uno size
# check ESISTE gia' (quindi il finding e' meno probabile / va derubricato)
_SIZE_CHECK_HINTS = [
    r"\bsizeof\s*\(",
    r"\bstrnlen\s*\(",
    r"\bstrlen\s*\([^)]*\)\s*[<>]=?",
    r"\bstrncpy\s*\(",
    r"\bstrncat\s*\(",
    r"\bsnprintf\s*\(",
    r"\bif\s*\([^)]*[<>]=?[^)]*\)",  # if con confronto (< <= > >=)
    r"\bmemset\s*\(",  # spesso segno di inizializzazione difensiva a monte
]

_SIZE_CHECK_RE = re.compile("|".join(_SIZE_CHECK_HINTS))

# Righe di contesto da guardare prima/dopo il match
WINDOW_BEFORE = 5
WINDOW_AFTER = 2


@dataclass
class ContextResult:
    context_checked: bool          # True = e' presente qualcosa che somiglia a un size check
    confidence: str                # "high" | "medium" | "low"
    window_snippet: str            # righe di contesto usate per la decisione, utile per il report


def _line_index_at_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset)


def analyze_match_context(function_text: str, match_offset: int, base_severity: str) -> ContextResult:
    """
    Valuta il contesto locale attorno a un match YARA all'interno del
    testo di UNA funzione decompilata.
    """
    lines = function_text.splitlines()
    match_line = _line_index_at_offset(function_text, match_offset)

    start = max(0, match_line - WINDOW_BEFORE)
    end = min(len(lines), match_line + WINDOW_AFTER + 1)
    window = "\n".join(lines[start:end])

    has_check = bool(_SIZE_CHECK_RE.search(window))

    if has_check:
        # C'e' un controllo vicino: probabile difesa gia' presente ->
        # non scartiamo il finding (potrebbe essere un controllo non
        # sufficiente), ma abbassiamo la confidenza.
        confidence = "low" if base_severity in ("Low", "Medium") else "medium"
    else:
        confidence = "high" if base_severity in ("High", "Critical") else "medium"

    return ContextResult(context_checked=has_check, confidence=confidence, window_snippet=window)
