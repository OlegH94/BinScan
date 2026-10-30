"""
accuracy.py
--------------------------------------------------------------------
Componente 4.1 dello spec ("Accuracy Testing: Test on binaries with
known vulnerabilities... Metrics: True positive rate, false positive
rate").

Il confronto e' possibile perche' i binari Juliet in bins/ NON sono
stripped (Ghidra preserva il nome originale delle funzioni): quindi
non serve mappare numeri di riga tra sorgente e pseudocodice
decompilato (che raramente corrispondono), basta confrontare per
NOME FUNZIONE + famiglia di CWE (vedi cwe_utils.is_related_cwe).

Il file di ground truth e' mantenuto A MANO dall'utente (non generato
automaticamente): un JSON in <project_root>/ground_truth.json, con
questa forma:

{
  "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01-bad": {
    "expected": [
      {"cwe": "CWE-121", "function": "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad"},
      {"cwe": "CWE-126", "function": "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad"}
    ]
  }
}

Un binario senza entry nel file di ground truth viene semplicemente
saltato nel calcolo di accuracy (non e' un errore: significa solo che
non avete ancora annotato la ground truth per quel binario).
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

try:
    from .cwe_utils import is_related_cwe
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from cwe_utils import is_related_cwe


@dataclass
class ExpectedFlaw:
    cwe: str
    function: str


@dataclass
class AccuracyResult:
    binary: str
    has_ground_truth: bool
    expected: list[ExpectedFlaw] = field(default_factory=list)
    true_positives: list[dict] = field(default_factory=list)   # expected flaw + quale motore l'ha trovato
    false_negatives: list[ExpectedFlaw] = field(default_factory=list)  # expected non trovati da nessun motore
    false_positives: list[dict] = field(default_factory=list)  # finding su funzioni non in ground truth
    per_engine_hits: dict[str, int] = field(default_factory=dict)  # quanti expected ogni motore ha trovato da solo

    @property
    def true_positive_rate(self) -> float | None:
        total_expected = len(self.expected)
        if total_expected == 0:
            return None
        return len(self.true_positives) / total_expected

    @property
    def false_positive_count(self) -> int:
        return len(self.false_positives)


def load_ground_truth(project_root: str | Path) -> dict:
    path = Path(project_root) / "ground_truth.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"[!] ground_truth.json non e' JSON valido, ignorato: {path}")
        return {}


def compute_accuracy(
    binary_name: str,
    findings_all: list[dict],
    ground_truth: dict,
) -> AccuracyResult:
    """
    findings_all: contenuto di findings_all.json (lista di finding gia'
    normalizzati a dict, con almeno "function", "cwe", "engine").
    ground_truth: il dict caricato da load_ground_truth() (chiave =
    nome binario).
    """
    entry = ground_truth.get(binary_name)
    if not entry:
        return AccuracyResult(binary=binary_name, has_ground_truth=False)

    expected = [ExpectedFlaw(cwe=e["cwe"], function=e["function"]) for e in entry.get("expected", [])]
    expected_functions = {e.function for e in expected}

    result = AccuracyResult(binary=binary_name, has_ground_truth=True, expected=expected)

    for flaw in expected:
        hit_engines = [
            f.get("engine", "yara")  # i finding YARA non hanno mai avuto "engine" prima del fix in pipe.py
            for f in findings_all
            if f.get("function") == flaw.function and is_related_cwe(f.get("cwe", ""), flaw.cwe)
        ]
        if hit_engines:
            result.true_positives.append({"cwe": flaw.cwe, "function": flaw.function, "engines": sorted(set(hit_engines))})
            for engine in set(hit_engines):
                result.per_engine_hits[engine] = result.per_engine_hits.get(engine, 0) + 1
        else:
            result.false_negatives.append(flaw)

    # Falsi positivi: finding su funzioni che la ground truth NON elenca
    # come vulnerabili per questo binario. E' un'approssimazione onesta:
    # non e' una verifica assoluta che quella funzione sia sicura, e'
    # un confronto contro quello che la ground truth annotata dichiara.
    for f in findings_all:
        func = f.get("function")
        if func and func not in expected_functions:
            result.false_positives.append({
                "function": func,
                "cwe": f.get("cwe", ""),
                "engine": f.get("engine", "yara"),
                "rule": f.get("rule", ""),
            })

    return result