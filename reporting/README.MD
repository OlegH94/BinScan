# reporting — Reporting Engine

Modulo del progetto di tesi (componente **2.5 — Reporting Engine**
della pipeline a 5 fasi). Aggrega finding (vuln_scanner), timing
(decompilazione + CFG) e, se annotata, l'accuracy contro una ground
truth, in due report: **HTML** interattivo (Jinja2) e **SARIF**
(per CI/CD, GitHub Code Scanning).

## Struttura

```
reporting/
├── README.md
├── cwe_utils.py          # parentela tra CWE (famiglie MITRE) + tabella remediation
├── accuracy.py           # confronto con ground_truth.json (TP/FP/FN)
├── code_context.py       # estrae il corpo di una funzione (decompilato/sorgente) per nome
├── chart_svg.py          # grafici a barre in SVG puro, incorporati nell'HTML
├── sarif_export.py       # esportazione SARIF 2.1.0
├── juliet_ground_truth_importer.py  # import ground_truth.json dal manifest Juliet + resolve_source_paths()
├── report_generator.py   # orchestratore: genera report.html + report.sarif
├── aggregate_report.py   # vista d'insieme su tutti i binari in risultati/
└── templates/
    ├── report.html.jinja2
    └── aggregate_report.html.jinja2
```

**Dipendenza nuova**: `pip install jinja2` (aggiungila al
`requirements.txt` che usi già per `vuln_scanner`, o installala a
parte).

## Timing (punto 4.3 dello spec — Performance)

`pipe.py` misura da solo la durata di decompilazione e costruzione
CFG con `time.perf_counter()`, e scrive `risultati/<nome_bin>/
timing.json`:

```json
{"decompile_seconds": 4.32, "cfg_seconds": 1.87, "binary_size_bytes": 17832}
```

Il report calcola anche i secondi/MB per la decompilazione, utile per
confrontare binari di dimensioni diverse. `timing.json` è su disco
(non solo in memoria durante l'esecuzione di `pipe.py`): puoi
rigenerare il report da solo in un secondo momento senza rilanciare
tutta la pipeline.

## Accuracy (punto 4.1 dello spec — Accuracy Testing)

Il confronto è possibile perché i binari Juliet in `bins/` **non sono
stripped**: Ghidra preserva il nome originale delle funzioni, quindi
non serve mappare numeri di riga tra sorgente e pseudocodice
decompilato (che raramente corrispondono) — basta confrontare per
**nome funzione + famiglia di CWE**.

Crea (a mano, non generato automaticamente) `ground_truth.json` nella
root del progetto:

```json
{
  "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01-bad": {
    "expected": [
      {"cwe": "CWE-121", "function": "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad"},
      {"cwe": "CWE-126", "function": "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad"}
    ]
  }
}
```

(il file XML di Juliet — `CWE121_..._01.c` ha spesso più di un
`<flaw>` per la stessa riga, come nel caso 121+126 già discusso:
mettili entrambi come voci separate).

Un binario **senza** entry in `ground_truth.json` non è un errore:
l'accuracy per quel binario resta semplicemente non calcolata, il
resto del report si genera comunque.

**Come funziona il confronto** (`accuracy.py`):
- **True Positive**: per ogni debolezza attesa, almeno un motore ha
  un finding sulla stessa funzione con un CWE della stessa famiglia
  (vedi sotto — non serve la stringa esatta);
- **False Negative**: nessun motore ha trovato quella debolezza attesa;
- **False Positive**: un finding su una funzione **non** elencata
  come vulnerabile per quel binario in `ground_truth.json` — è
  un'approssimazione onesta: presuppone che la ground truth sia
  completa, non è una verifica assoluta che quella funzione sia sicura.

Il report mostra anche un confronto **per motore**: quanti degli
`expected` ciascun motore (YARA, semgrep, cwe_checker) ha trovato da
solo — utile per il capitolo di confronto tra i tre motori.

## Codice della funzione al posto della riga (`code_context.py`)

Ogni finding mostrava finora solo `Riga: N` — un numero che, per il
pseudocodice decompilato da Ghidra, non e' sempre allineato a un
conteggio "riga per riga" fatto in un editor qualsiasi: Ghidra inserisce
spesso righe vuote tra la firma di una funzione e la graffa di apertura,
e tra le dichiarazioni delle variabili locali.

Il report ora individua la funzione **per nome** (stessa strategia gia'
usata da `accuracy.py` per il confronto con la ground truth) e ne mostra
il **corpo intero**, con la riga che ha fatto scattare il finding
evidenziata (sfondo scuro, bordo arancione a sinistra) — cosi' il punto
esatto resta individuabile anche se un numero di riga sarebbe stato
ambiguo. Se e' disponibile anche il sorgente originale, viene mostrato
un secondo pannello con la stessa funzione nel `.c` reale, per un
confronto diretto decompilato/sorgente.

Per attivarlo, passa a `generate_report()`:

- `decompiled_c_path`: path al pseudocodice completo decompilato da
  Ghidra per il binario (tutte le funzioni in un unico file — il tipico
  output di `decompiler.py`);
- `source_c_paths`: uno o piu' path al sorgente `.c` originale (piu' di
  uno per i testcase Juliet a file separati, es. `..._51a.c` +
  `..._51b.c`). Per i binari Juliet, `juliet_ground_truth_importer.
  resolve_source_paths(binary_name, manifest_xml_path, sources_dir)`
  li risolve automaticamente dal manifest, con la stessa convenzione di
  naming gia' usata per costruire `ground_truth.json` — evita di dover
  indovinare a mano la corrispondenza binario -> file sorgente.

Entrambi i parametri sono opzionali e degradano con grazia: senza di
essi (o se il file indicato non esiste), il report mostra solo la
singola riga trovata (`matched_line`), com'era prima.

## Grafici (`chart_svg.py`)

Un piccolo generatore di grafici a barre in **SVG puro**, senza
dipendenze aggiuntive (nessun matplotlib): l'SVG e' incorporato
direttamente nell'HTML, non e' un file immagine separato da servire.

- **Report singolo**: nella sezione Riepilogo, un grafico "finding per
  motore" accanto alle metric-box gia' esistenti.
- **Report aggregato**: due grafici — finding totali per motore su
  tutto il batch, e la distribuzione TP/FN/FP complessiva (quando
  almeno un binario ha una ground truth annotata).

`bar_chart_svg(dati)` ritorna `None` se non c'e' nulla da disegnare
(dizionario vuoto o tutti valori a zero): i template omettono la
sezione in quel caso, niente grafici vuoti e fuorvianti.



Come discusso durante lo sviluppo del vuln_scanner: i tre motori
spesso riportano CWE diversi per lo stesso bug reale (CWE-121 è figlio
di CWE-119 nella tassonomia MITRE; CWE-125/787 sono varianti sorelle).
Un confronto a stringa esatta contro la ground truth Juliet darebbe
troppi falsi negativi. `is_related_cwe()` risolve confrontando per
**famiglia**, non per stringa — la famiglia attuale copre CWE-119/120/
121/122/124/125/126/127/131/242/787. Aggiungete altre famiglie in
`_CWE_FAMILIES` quando il vuln_scanner coprirà altre categorie oltre
al buffer overflow.

## Remediation (punto 3 dello spec)

`cwe_utils.suggest_remediation(rule, cwe)` — tabella statica
rule→testo (prima scelta) o CWE→testo (fallback), es. "sostituire
strcpy() con strncpy() o snprintf()". Non è esaustiva come una guida
OWASP, è pensata per comparire diretta nel report accanto a ogni
finding.

## SARIF (`sarif_export.py`)

Un `run` separato per ogni motore presente nei finding (così GitHub
Code Scanning mostra correttamente la provenienza), livello di
severità mappato sui tre livelli standard SARIF
(`error`/`warning`/`note`). Validato con `report.sarif` importabile
in un JSON schema SARIF 2.1.0 di base.

## Fuzzing (non ancora collegato)

Il template HTML ha già una sezione "Fuzzing" che mostra il corpus di
seed generato (da `fuzz_seed_generator`, se `manifest.json` esiste) e
una tabella di confronto "con seed guidati vs seed casuali" — quella
tabella resta vuota finché non avrete davvero eseguito una campagna
AFL++ e passato i numeri a `generate_report(..., fuzzing_effectiveness=[...])`.
La forma attesa di ogni riga:

```python
[{"metric": "Crash trovati", "with_seeds": "12", "without_seeds": "3"}, ...]
```

Coerente con la scelta di tenere l'esecuzione del fuzzing come
funzione a parte in `pipe.py`, volutamente disaccoppiata.

## Uso

Da `pipe.py` (gia' collegato, `_phase_reporting` gira come ultimo
passo per ogni binario) — **nota**: i due parametri
`decompiled_c_path`/`source_c_paths` sono nuovi e non ancora collegati
in `pipe.py`, vanno aggiunti a mano nella chiamata esistente:

```python
from reporting.report_generator import generate_report
from reporting.juliet_ground_truth_importer import resolve_source_paths

# opzionale: risolve i sorgenti originali dal manifest Juliet, se disponibile
source_paths = resolve_source_paths(
    binary_name="CWE121_..._01-bad",
    manifest_xml_path="sources/manifest.xml",
    sources_dir="sources/",
)

summary = generate_report(
    binary_name="CWE121_..._01-bad",
    findings_all_json="risultati/<nome_bin>/vuln_scanner/findings_all.json",
    output_dir="risultati/<nome_bin>/reporting",
    timing={"decompile_seconds": 4.3, "cfg_seconds": 1.9, "binary_size_bytes": 17832},
    project_root=".",  # per trovare ground_truth.json
    decompiled_c_path="risultati/<nome_bin>/decompiled/decompiled.c",  # adatta al path reale scritto da decompiler.py
    source_c_paths=source_paths,
)
```

Da CLI, per rigenerare un report senza rilanciare tutta la pipeline:

```bash
python reporting/report_generator.py \
    --binary CWE121_..._01-bad \
    --findings risultati/<nome_bin>/vuln_scanner/findings_all.json \
    --output risultati/<nome_bin>/reporting \
    --timing risultati/<nome_bin>/timing.json \
    --project-root . \
    --decompiled risultati/<nome_bin>/decompiled/decompiled.c \
    --source sources/CWE121_..._01.c
```