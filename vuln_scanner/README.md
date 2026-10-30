# vuln_scanner — Vulnerability Pattern Scanner (Buffer Overflow)

Modulo del progetto di tesi (componente **2.3 — Vulnerability Pattern
Scanner** della pipeline a 5 fasi), integrato in `pipe.py`. Copre **solo
i pattern di Buffer Overflow** (CWE-119/120/121/125/787) su
pseudocodice C decompilato con Ghidra e sul binario stesso.

Tre motori di scansione **indipendenti**, eseguiti in parallelo da
`pipe.py` (nessuno sostituisce gli altri — l'idea e' confrontare in
tesi dove concordano e dove no):

1. **YARA + context analyzer + taint analysis fatta a mano**
   (`scanner.py`, `context_analyzer.py`, `taint_analysis.py`) — il
   motore originale, regex su pseudocodice testuale.
2. **semgrep** (`semgrep_scanner.py`, `semgrep_rules/`) — stesse
   categorie di pattern ma con parsing AST reale (tree-sitter), piu'
   un **taint mode nativo** di semgrep come secondo tracciamento
   indipendente dalla `taint_analysis.py` custom.
3. **cwe_checker** (`cwe_checker_integration.py`) — abstract
   interpretation su Ghidra Pcode via Docker, gira sul **binario**
   (non sullo pseudocodice) ed e' il sostituto di BinAbsInspector
   (fermo al 2022, non compatibile con Ghidra 12+): cwe_checker e'
   attivamente mantenuto e copre CWE-119/125/787 nativamente.

Le altre categorie CWE (use-after-free, integer overflow come classe
a se', ecc.) restano fuori scope per ora, tranne quelle che
cwe_checker riporta comunque essendo un tool generico.

## Struttura

```
vuln_scanner/
├── README.md
├── requirements.txt
├── ghidra_types.h               # typedef Ghidra (undefined4, uint, ...) per far parsare lo pseudocodice a semgrep
├── yara_rules/
│   └── buffer_overflow.yar      # motore 1: regole YARA
├── context_analyzer.py          # motore 1: approssima le condizioni che YARA non esprime
├── taint_analysis.py            # motore 1: taint tracking statico intraprocedurale (fatto a mano)
├── scanner.py                   # motore 1: orchestratore + run_scan() (usato da pipe.py) + CLI
├── semgrep_rules/
│   └── buffer_overflow.yml      # motore 2: pattern "candidati" + regole taint-mode native
├── semgrep_scanner.py           # motore 2: wrapper + run_semgrep_scan() (usato da pipe.py) + CLI
├── cwe_checker_integration.py   # motore 3: wrapper Docker + run_cwe_checker() (usato da pipe.py) + CLI
└── tests/
    └── sample_vulnerable.c      # caso di prova con i vari pattern (usato da tutti e tre i motori)
```

Non c'e' uno script di export da Ghidra dedicato: `decompiler/
DecompScript.java` produce gia' un unico file
`<binario>_decompiled.c` con tutte le funzioni concatenate, e lo
splitter di `scanner.py` (`split_into_functions`) lo spezza in
funzioni riconoscendo la firma `tipo nome(...) {` — stesso formato
prodotto da `DecompInterface.getC()` che gia' usate. Quindi l'input
del modulo e' direttamente l'output della fase di decompilazione
esistente, nessun passaggio in piu' da fare.

## Perché YARA da solo non basta

Le "regole YARA-like" con `condition: "no_size_check(dest, src)"`
sono pseudocodice illustrativo, non sintassi YARA valida: YARA fa
pattern matching testuale/regex, non ha visibilità sul flusso di
controllo o sulle variabili. Per questo il modulo è diviso in due
livelli:

1. **`yara_rules/buffer_overflow.yar`** — regole YARA vere che
   individuano i *candidati*: `strcpy`/`strcat` non delimitati,
   `gets`, `sprintf` al posto di `snprintf`, `memcpy`/`memmove` con
   size dinamica, `scanf("%s")` senza larghezza massima, buffer su
   stack seguiti da `read`/`recv`, `alloca` dinamico, scritture in
   array dentro loop, format string sospette.
2. **`context_analyzer.py`** — implementa concretamente il
   "no_size_check": guarda una finestra di righe attorno al match
   cercando `sizeof`, `strlen(...) <`, `strncpy`/`snprintf`, un `if`
   con confronto. Non scarta mai un finding — se trova un controllo,
   abbassa solo la `confidence`, per non perdere veri positivi.

## Taint analysis

`taint_analysis.py` fa una taint analysis statica **intraprocedurale**,
riga per riga: source = `read`/`recv`/`fgets`/`scanf`/`getenv`/
`argv`/`fread`; propaga attraverso assegnazioni e chiamate copy;
marca il finding `tainted: true` con la riga sorgente che ha
introdotto il taint.

**Limiti dichiarati** (da mettere in tesi): è intraprocedurale (non
segue il taint attraverso funzioni custom del binario — estensione
naturale per lavori futuri, visto che angr con il CFG è già nella
pipeline); si basa su regex su righe di pseudocodice, non su un AST.

## Motore 2: semgrep (parallelo, non sostitutivo)

Stesso pseudocodice, parsing reale invece di regex: semgrep costruisce
un AST tramite tree-sitter, quindi non si fa ingannare da chiamate su
più righe, spazi variabili, o commenti in mezzo agli argomenti — cose
su cui una regex YARA può inciampare. Le regole "candidate" in
`semgrep_rules/buffer_overflow.yml` rispecchiano quelle YARA (stessi
CWE, stessa logica).

Le regole `bof-tainted-*` usano invece il **taint mode nativo** di
semgrep: source (`read`/`recv`/`fgets`/`fread`/...) → sink
(`strcpy`/`memcpy`/`printf`/...), con sanitizer (`strncpy`,
`snprintf`, ...). È un secondo motore di taint tracking, scritto in
un linguaggio dichiarativo diverso e mantenuto da altri — utile come
cross-check rispetto alla `taint_analysis.py` fatta a mano: nel test
case incluso, entrambi individuano la stessa catena `recv → strcpy`.

**Nota tecnica non ovvia**: le funzioni come `recv`/`fgets` scrivono
il dato nel buffer passato come argomento (by-reference), non lo
restituiscono. Il taint mode di semgrep di default marca come
"sporco" solo il **valore di ritorno** di una source — per fargli
capire che è l'argomento a diventare tainted serve l'opzione
`by-side-effect: true` insieme a `focus-metavariable` (vedi i
commenti nel file `.yml`). Senza questo dettaglio le regole taint
compilano senza errori ma non trovano mai nulla — è stato verificato
sperimentalmente durante lo sviluppo del modulo.

Lo pseudocodice Ghidra usa typedef non standard (`undefined4`, `uint`,
`code`, ...) che il parser di semgrep non conosce: `ghidra_types.h`
viene anteposto in memoria al file prima dell'analisi (mai scritto
dentro `decompiled_files/`), e gli offset di riga nei risultati
vengono ricorretti sottraendo le righe dell'header.

## Motore 3: cwe_checker (sostituto di BinAbsInspector)

BinAbsInspector (Java, Ghidra extension) è fermo al 2022 e non
compatibile con Ghidra 12+; **cwe_checker** (Fraunhofer FKIE) fa lo
stesso tipo di analisi (abstract interpretation su Ghidra Pcode) ma è
attivamente mantenuto e gira via Docker, senza build da sorgente:

```bash
docker pull ghcr.io/fkie-cad/cwe_checker:stable   # una tantum
```

A differenza dei motori 1 e 2, cwe_checker analizza **il binario**,
non lo pseudocodice — copre nativamente CWE-119 (Buffer Overflow) e
le varianti CWE-125/CWE-787. **CWE-121** (Stack-Based Buffer
Overflow, quello dei tuoi test case Juliet) è un CWE **figlio** di
CWE-119 nella tassonomia MITRE: cwe_checker riporta "CWE119"/"CWE787",
non letteralmente "CWE121" — è la classificazione corretta al livello
di parent, va solo tenuto presente quando confronti i risultati con
l'etichetta dei tuoi file di test nel Reporting Engine.

Se `symbols_json` è disponibile (quello prodotto da
`decompiler.decompile()`), `run_cwe_checker()` risolve gli indirizzi
riportati da cwe_checker al nome della funzione corrispondente, così
i risultati sono confrontabili per nome funzione con quelli di YARA e
semgrep. Verifica lo schema JSON reale con una scansione di prova
prima di fidarti ciecamente della normalizzazione: è basata sulla
documentazione pubblica del progetto, non su un output visto
direttamente (nessun ambiente Docker disponibile in fase di sviluppo
di questo modulo).

## Uso

Da `pipe.py` (già collegato, i tre motori girano in sequenza per ogni
binario — vedi `_phase_vuln_scanner` in `pipe.py`):

```python
from vuln_scanner.scanner import run_scan
from vuln_scanner.semgrep_scanner import run_semgrep_scan
from vuln_scanner.cwe_checker_integration import run_cwe_checker

yara_findings = run_scan(decompiled_c_path, output_json_path)
semgrep_findings = run_semgrep_scan(decompiled_c_path, output_json_path)
cwe_checker_findings = run_cwe_checker(binary_path, output_json_path, symbols_json_path)
```

Da CLI, in autonomia:

```bash
pip install -r vuln_scanner/requirements.txt   # yara-python + semgrep
docker pull ghcr.io/fkie-cad/cwe_checker:stable

python vuln_scanner/scanner.py         --input risultati/<nome_bin>/decompiled_files/ --output findings_yara.json
python vuln_scanner/semgrep_scanner.py --input risultati/<nome_bin>/decompiled_files/ --output findings_semgrep.json
python vuln_scanner/cwe_checker_integration.py --binary risultati/<nome_bin>/bin/<nome_bin> --output findings_cwe.json
```

## Output

Un array JSON di oggetti come:

```json
{
  "rule": "BOF_Unbounded_Strcpy",
  "description": "Uso di strcpy senza controllo di dimensione",
  "severity": "High",
  "cwe": "CWE-120",
  "function": "vulnerable_taint_chain",
  "file": "...decompiled.c",
  "line": 8,
  "matched_line": "strcpy(local_10,local_50);",
  "context_checked": false,
  "confidence": "high",
  "tainted": true,
  "taint_sources": ["iVar1 = recv(param_1,local_50,0x400,0);"]
}
```

Pensato per essere consumato direttamente dal **Reporting Engine**
(componente successivo della pipeline).

## Testare con i tuoi test case

`tests/sample_vulnerable.c` è solo uno smoke test minimo (6 pattern
impiantati, 0 falsi positivi sulla funzione "safe"). Per i tuoi test
case reali: mettili in una cartella e passala con `--input`, oppure
punta direttamente a `risultati/<nome_bin>/decompiled_files/` dopo
che la pipeline ha girato.

## Limitazioni generali

- Analisi statica su pseudocodice testuale, non sul CFG reale.
- Context analyzer euristico a finestra di righe, non un vero
  data-flow.
- Taint analysis intraprocedurale.
- Regole calibrate su pseudocodice Ghidra (naming `local_28`,
  `param_1`); su altri decompilatori i pattern di chiamata restano
  validi ma il naming andrebbe verificato.
