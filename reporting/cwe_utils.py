"""
cwe_utils.py
--------------------------------------------------------------------
Due utilita' condivise dal Reporting Engine:

1. Parentela tra CWE: come discusso durante lo sviluppo del
   vuln_scanner, i tre motori (YARA, semgrep, cwe_checker) spesso
   riportano CWE diversi per LO STESSO bug reale, perche' ciascuno
   classifica al livello di dettaglio che riesce a vedere (es.
   CWE-121 "Stack-based Buffer Overflow" e' un figlio di CWE-119
   "Improper Restriction of Operations within Bounds of a Memory
   Buffer" nella tassonomia MITRE; CWE-125/787 sono varianti
   sorelle). Un confronto a stringa esatta contro la ground truth
   Juliet darebbe troppi falsi negativi nell'accuracy testing.
   is_related_cwe() risolve questo confrontando per FAMIGLIA, non
   per stringa.

2. Suggerimenti di remediation: una tabella statica rule/CWE ->
   testo di correzione, per il punto 3 dello spec ("Remediation
   Suggestions: Provide code fixes").
--------------------------------------------------------------------
"""

from __future__ import annotations

# Famiglie di CWE trattate come equivalenti ai fini del confronto con
# la ground truth (tutte riconducibili, nella tassonomia MITRE, allo
# stesso problema di fondo: accesso fuori dai limiti di un buffer).
# Aggiungete qui altre famiglie quando il vuln_scanner coprira' altre
# categorie oltre al buffer overflow.
_CWE_FAMILIES: list[set[str]] = [
    {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125",
     "CWE-126", "CWE-127", "CWE-131", "CWE-787", "CWE-242"},
]


def _normalize(cwe: str) -> str:
    cwe = cwe.strip().upper()
    if cwe and not cwe.startswith("CWE-") and cwe.startswith("CWE"):
        cwe = "CWE-" + cwe[3:]
    return cwe


def is_related_cwe(reported: str, expected: str) -> bool:
    """
    True se `reported` ed `expected` sono lo stesso CWE, o appartengono
    alla stessa famiglia (es. CWE-787 riportato da semgrep e CWE-121
    della ground truth Juliet sono "la stessa cosa" ai fini
    dell'accuracy testing — vedi il modulo docstring).
    """
    r, e = _normalize(reported), _normalize(expected)
    if not r or not e:
        return False
    if r == e:
        return True
    return any(r in fam and e in fam for fam in _CWE_FAMILIES)


# ---------------------------------------------------------------------
# Suggerimenti di remediation. Chiave = nome regola (vuln_scanner) o,
# in fallback, il CWE del finding. Testo pensato per comparire diretto
# nel report, non per essere esaustivo come una guida OWASP.
# ---------------------------------------------------------------------

REMEDIATION_BY_RULE: dict[str, str] = {
    "BOF_Unbounded_Strcpy": "Sostituire strcpy() con strncpy() o snprintf(), specificando esplicitamente la dimensione del buffer di destinazione.",
    "BOF_Unbounded_Strcat": "Sostituire strcat() con strncat(), o meglio con snprintf() per costruire la stringa concatenata con un limite esplicito.",
    "BOF_Gets_Call": "gets() non ha modo di limitare la lettura: sostituire con fgets(buf, sizeof(buf), stdin).",
    "BOF_Sprintf_No_Bound": "Sostituire sprintf() con snprintf(), specificando la dimensione del buffer di destinazione.",
    "BOF_Vsprintf_No_Bound": "Sostituire vsprintf() con vsnprintf(), specificando la dimensione del buffer di destinazione.",
    "BOF_Memcpy_Suspicious_Size": "Verificare che il terzo argomento di memcpy() non superi mai sizeof(destinazione); se la size proviene da input esterno, validarla esplicitamente prima della copia.",
    "BOF_Memmove_Suspicious_Size": "Verificare che il terzo argomento di memmove() non superi mai sizeof(destinazione).",
    "BOF_Const_Size_Exceeds_Declared_Buffer": "La dimensione copiata supera quella dichiarata del buffer: usare sizeof(buffer_destinazione) invece di una costante calcolata su un tipo/struct diverso (causa tipica: sizeof(struct) invece di sizeof(campo)).",
    "BOF_Scanf_Unbounded_String": "Specificare una larghezza massima di campo nel format string (es. \"%63s\" per un buffer di 64 byte) o usare fgets() seguito da parsing manuale.",
    "BOF_Stack_Buffer_Plus_Read": "Verificare che la size passata a read()/recv() non superi mai la dimensione del buffer di destinazione dichiarato sullo stack.",
    "BOF_Alloca_Dynamic_Size": "alloca() con size non costante puo' esaurire lo stack in modo controllato dall'attaccante: preferire malloc()/free() con un limite massimo esplicito validato.",
    "BOF_Array_Index_No_Bound_Check": "Aggiungere un controllo esplicito dell'indice contro i limiti dell'array prima di ogni accesso in scrittura dentro il ciclo.",
    "BOF_Format_String_To_Buffer": "Non passare mai una stringa proveniente da input come primo argomento di printf-family: usare printf(\"%s\", input) invece di printf(input).",
}

REMEDIATION_BY_CWE: dict[str, str] = {
    "CWE-120": "Validare sempre la dimensione dei dati copiati contro la dimensione reale del buffer di destinazione prima di qualunque operazione di copia.",
    "CWE-121": "Validare la dimensione di ogni scrittura su buffer allocati sullo stack; preferire funzioni con limite esplicito (snprintf, strncpy) alle loro controparti non delimitate.",
    "CWE-125": "Validare che ogni lettura non acceda oltre la dimensione effettiva del buffer/stringa sorgente.",
    "CWE-131": "Ricalcolare la dimensione di allocazione usando sizeof() sul tipo corretto, non su un tipo correlato ma diverso.",
    "CWE-134": "Non usare mai dati esterni come stringa di formato: passarli sempre come argomento (es. printf(\"%s\", buf)).",
    "CWE-242": "Sostituire funzioni intrinsecamente insicure (gets) con le loro controparti delimitate (fgets).",
    "CWE-787": "Validare ogni scrittura contro i limiti reali del buffer di destinazione prima di eseguirla.",
}

_GENERIC_REMEDIATION = "Rivedere manualmente il punto segnalato: verificare che ogni scrittura/lettura sia delimitata dalla dimensione reale del buffer coinvolto."


def suggest_remediation(rule: str | None, cwe: str | None) -> str:
    if rule and rule in REMEDIATION_BY_RULE:
        return REMEDIATION_BY_RULE[rule]
    if cwe:
        normalized = _normalize(cwe)
        if normalized in REMEDIATION_BY_CWE:
            return REMEDIATION_BY_CWE[normalized]
    return _GENERIC_REMEDIATION