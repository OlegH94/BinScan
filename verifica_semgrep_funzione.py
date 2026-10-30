"""
verifica_semgrep_funzione.py
Assegna a ogni finding di Semgrep la funzione che lo contiene (ricavata dal numero
di riga nel file decompilato) e ricalcola il tasso di veri positivi con e senza
i finding di Semgrep. Non modifica nessun file dei risultati.

Uso (dalla cartella BinScan):
    python verifica_semgrep_funzione.py <cartella_risultati> <ground_truth.json>
"""
import json, re, sys
from pathlib import Path
from reporting.cwe_utils import is_related_cwe

def mappa_righe(testo):
    """numero di riga (1-based) -> nome della funzione che la contiene"""
    righe = testo.split("\n"); out = {}; corrente = None; i = 0
    while i < len(righe):
        if righe[i].startswith("{") and corrente is None:
            j = i - 1; firma = ""
            while j >= 0 and not righe[j].strip(): j -= 1   # Ghidra lascia righe vuote tra firma e graffa
            while j >= 0 and righe[j].strip() and not righe[j].startswith("}"):
                firma = righe[j] + " " + firma; j -= 1
            m = re.search(r"([A-Za-z_]\w*)\s*\(", firma)
            corrente = m.group(1) if m else "?"
            for k in range(j + 1, i + 1): out[k + 1] = corrente
        elif righe[i].startswith("}"):
            out[i + 1] = corrente; corrente = None
        elif corrente is not None:
            out[i + 1] = corrente
        i += 1
    return out

ris = Path(sys.argv[1]); gt = json.load(open(sys.argv[2], encoding="utf-8"))
attese = tp_senza = tp_con = 0; n_sem = n_assegnati = sem_in_attesa = sem_fuori = 0
recuperati = []
for binario, voce in sorted(gt.items()):
    d = ris / binario
    if not d.exists(): continue
    tutti = json.load(open(d / "vuln_scanner" / "findings_all.json", encoding="utf-8"))
    sem = json.load(open(d / "vuln_scanner" / "findings_semgrep.json", encoding="utf-8"))
    dec = next((d / "decompiled_files").glob("*_decompiled.c")).read_text(encoding="utf-8", errors="replace")
    mappa = mappa_righe(dec)
    funzioni_attese = {e["function"] for e in voce["expected"]}
    sem_f = []
    for f in sem:
        n_sem += 1
        fn = mappa.get(f.get("line"))
        if fn: n_assegnati += 1
        if fn in funzioni_attese: sem_in_attesa += 1
        elif fn: sem_fuori += 1
        sem_f.append({**f, "function": fn})
    for e in voce["expected"]:
        attese += 1
        base = any(f.get("function") == e["function"] and is_related_cwe(f.get("cwe", ""), e["cwe"]) for f in tutti)
        extra = any(f["function"] == e["function"] and is_related_cwe(f.get("cwe", ""), e["cwe"]) for f in sem_f)
        tp_senza += base; tp_con += (base or extra)
        if extra and not base: recuperati.append((binario, e["cwe"]))
print(f"Finding Semgrep: {n_sem}, con funzione assegnata: {n_assegnati}")
print(f"  nella funzione attesa: {sem_in_attesa}   in altre funzioni (falsi positivi): {sem_fuori}")
print(f"TPR senza Semgrep (framework attuale): {tp_senza}/{attese} = {100*tp_senza/attese:.1f}%")
print(f"TPR con Semgrep:                       {tp_con}/{attese} = {100*tp_con/attese:.1f}%")
print("Debolezze recuperate solo grazie a Semgrep:")
for r in recuperati: print("  ", r)
