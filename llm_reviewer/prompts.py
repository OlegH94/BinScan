"""
prompts.py
--------------------------------------------------------------------
Template dei prompt per llm_review.py, separati dalla logica di
chiamata per poter tarare il testo senza toccare il resto del codice.

Chiediamo esplicitamente output JSON strutturato (Ollama supporta
format="json" per forzare risposte valide) per poter integrare il
verdetto nello stesso schema degli altri motori senza dover fare
parsing di linguaggio naturale libero.
--------------------------------------------------------------------
"""

from __future__ import annotations

_SYSTEM_CONTEXT = """Sei un revisore di sicurezza che analizza pseudocodice C prodotto dal decompilatore Ghidra.
Lo pseudocodice usa naming non standard tipico di Ghidra: variabili come local_28, param_1, uVar1,
tipi come undefined4, undefined8, uint, byte. Ignora questi dettagli stilistici e concentrati sulla logica.

Il tuo compito e' valutare se la funzione contiene un buffer overflow (CWE-119 e le sue varianti:
CWE-120, CWE-121 stack-based, CWE-122 heap-based, CWE-125 out-of-bounds read, CWE-131 dimensione
di allocazione calcolata male, CWE-787 out-of-bounds write).

Presta particolare attenzione a:
- scritture tramite puntatore con offset che potrebbero superare la dimensione dichiarata di un buffer
- chiamate a memcpy/memmove/strcpy/strcat/sprintf/snprintf/strncpy/strncat con una size sospetta
- cicli che scrivono in un array con un limite che potrebbe superarne la dimensione
- casi in cui il compilatore potrebbe aver eliminato una chiamata a funzione di libreria sostituendola
  con assegnazioni dirette (memset seguito da una sequenza di scritture manuali via puntatore e' un
  indizio tipico di una memcpy/memmove srotolata dal compilatore)

Rispondi SOLO con un oggetto JSON valido, senza testo aggiuntivo prima o dopo, con questa forma esatta:
{"vulnerable": true/false, "cwe": "CWE-XXX o null se non applicabile", "confidence": "high/medium/low",
 "explanation": "spiegazione in 1-2 frasi, in italiano"}
"""


def build_review_prompt(function_name: str, pseudocode: str, other_engine_findings: list[dict]) -> str:
    """
    other_engine_findings: i finding gia' prodotti da YARA/semgrep/cwe_checker
    per QUESTA funzione (puo' essere vuota: in quel caso stiamo chiedendo una
    seconda opinione indipendente, non una conferma di qualcosa gia' trovato).
    """
    if other_engine_findings:
        findings_summary = "\n".join(
            f"- {f.get('engine', '?')}: regola/CWE '{f.get('rule') or f.get('cwe', '?')}', "
            f"descrizione: {f.get('description', 'n/d')}"
            for f in other_engine_findings
        )
        context = (
            f"Altri motori di analisi statica hanno gia' segnalato questa funzione:\n{findings_summary}\n\n"
            f"Valuta se questi finding sono plausibili (vero positivo) o probabili falsi positivi, "
            f"e se manca qualcosa che gli altri motori non hanno visto."
        )
    else:
        context = (
            "Nessun motore di analisi statica (pattern matching su testo/AST, interpretazione astratta "
            "sul binario) ha segnalato nulla per questa funzione. Fai una revisione indipendente: "
            "potrebbe esserci un bug che quei motori non riescono a vedere (es. una copia di memoria "
            "srotolata dal compilatore in assegnazioni dirette, invece di una chiamata a funzione "
            "riconoscibile testualmente)."
        )

    return (
        f"{_SYSTEM_CONTEXT}\n\n"
        f"Funzione da analizzare: {function_name}\n\n"
        f"{context}\n\n"
        f"Pseudocodice:\n```c\n{pseudocode}\n```\n"
    )