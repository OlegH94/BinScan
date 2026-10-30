# llm_reviewer — Quarto motore di revisione (LLM locale)

Modulo **autonomo e volutamente disaccoppiato** dalla pipeline
principale (`pipe.py`) — stessa filosofia già usata per il fuzzing:
si lancia a parte, scrive nella sua cartella, con il suo report.

## Perché separato dagli altri tre motori

Un giudizio di un LLM è **probabilistico**, non una prova
deterministica come pattern matching (YARA), parsing AST (semgrep),
o interpretazione astratta (cwe_checker). Mescolarlo alla pari nei
tre motori principali (stesso `findings_all.json`, stessa accuracy)
renderebbe scorretto il confronto in tesi — per questo scrive in una
cartella propria (`llm_review/`) con un report proprio
(`review.html`), e va citato come quarta fonte di evidenza distinta,
non un quarto motore equivalente ai primi tre.

## Perché due modalità di revisione, non una sola

1. **Conferma sui candidati già segnalati** — per ogni funzione con
   almeno un finding da YARA/semgrep/cwe_checker, il modello riceve
   il contesto (chi ha segnalato cosa) e valuta plausibilità/falsi
   positivi.
2. **Seconda opinione indipendente sulle funzioni davvero raggiunte
   da `main()`, SEMPRE** — anche quando tutti e tre gli altri motori
   danno zero. Usa il call graph reale (`CFG/callgraph_named.graphml`,
   già prodotto dalla pipeline) per trovare solo le funzioni
   effettivamente eseguite a partire dall'entry point — non le
   dichiarazioni di funzioni di libreria che Ghidra stampa per la
   risoluzione dei simboli ma che il programma non chiama mai, né gli
   stub morti mai raggiunti. Generalizza a qualsiasi binario, non solo
   a questo dataset sintetico. **Fallback**: se il call graph manca o
   non ha un nodo `main` riconoscibile, analizza semplicemente
   `main()` stesso — nessuna convenzione di naming specifica del
   dataset (niente equivalente di "`_bad`" su un binario reale).

   Questo attacca direttamente i casi già diagnosticati durante lo
   sviluppo del vuln_scanner dove il **compilatore elimina la
   chiamata a funzione** (una `memmove` sostituita da costanti
   esadecimali, una `memcpy` "srotolata" in una sequenza di
   assegnazioni dirette via puntatore): pattern per costruzione
   invisibili a un motore che cerca `memcpy(...)` nel testo, ma che
   un modello che "legge" la logica del codice può notare.

## Setup (Ollama locale)

```bash
# 1. Installa Ollama da https://ollama.com (Windows: installer .exe)
# 2. Scarica il modello (una tantum, alcuni GB)
ollama pull qwen2.5-coder:7b
# 3. Verifica che sia in esecuzione (di solito parte da solo in background)
ollama list
```

Nessuna GPU richiesta — gira su CPU, più lento di un modello via API
ma gratuito e locale. Su un i5 senza GPU, aspettati qualche secondo
per funzione: per questo la selezione delle funzioni da rivedere è
mirata (solo candidati flaggati + funzione `_bad`), non l'intero file.

## Struttura

```
llm_reviewer/
├── README.md
├── prompts.py      # template del prompt, separato dalla logica di chiamata
└── llm_review.py   # chiamata a Ollama, selezione funzioni, output JSON+HTML
    templates/
    └── review.html.jinja2
```

## Uso

Da libreria:
```python
from llm_reviewer.llm_review import review_binary

entries = review_binary(
    decompiled_c_path="risultati/<nome_bin>/decompiled_files/<nome_bin>_decompiled.c",
    findings_all_json="risultati/<nome_bin>/vuln_scanner/findings_all.json",  # opzionale
    output_dir="risultati/<nome_bin>/llm_review",
)
```

Da CLI, su un binario singolo:
```bash
python llm_reviewer/llm_review.py \
    --decompiled risultati/<nome_bin>/decompiled_files/<nome_bin>_decompiled.c \
    --findings risultati/<nome_bin>/vuln_scanner/findings_all.json \
    --output risultati/<nome_bin>/llm_review
```

Su tutto il batch (script dedicato, stesso pattern di
`rerun_scanning.py`):
```bash
python run_llm_review.py                    # tutti i binari in risultati/
python run_llm_review.py --only NOME_BIN    # solo uno
```

## Output

`review.json` — un array di oggetti:
```json
{
  "function": "CWE121_..._01_bad",
  "file": "..._decompiled.c",
  "reviewed_because": "reachable_from_main",
  "other_engine_findings": [],
  "vulnerable": true,
  "cwe": "CWE-787",
  "confidence": "high",
  "explanation": "..."
}
```

`review.html` — report leggibile, con avviso ben visibile sulla
natura probabilistica del giudizio.

## Limiti onesti (da mettere in tesi)

- **Nessuna garanzia di accuratezza**: un LLM può allucinare un CWE
  plausibile ma sbagliato, o mancare un bug reale. Va trattato come
  un "secondo parere" da verificare, non come verdetto finale.
- **Modello locale quantizzato** (non il modello "pieno"): qualità
  inferiore a un modello via API più grande, in cambio di girare
  gratis su CPU senza dipendenze esterne.
- **Parsing JSON difensivo ma non infallibile**: se il modello non
  rispetta il formato richiesto, l'entry viene comunque salvata con
  `parse_error: true` e una spiegazione, invece di far fallire tutto
  il batch — ma quell'entry specifica non ha un giudizio affidabile.
- **Il criterio "raggiungibile da main()" dipende dal call graph**:
  se `angr` non è riuscito a costruire un call graph affidabile per
  un binario (packing, offuscamento, architetture insolite), il
  criterio ricade su "analizza solo main()" — meno mirato, ma non
  richiede alcuna convenzione specifica del dataset per funzionare
  su un binario reale.