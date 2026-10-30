# fuzz_seed_generator — Fuzzer Seed Generator

Modulo del progetto di tesi (componente **2.4 — Fuzzer Seed
Generator** della pipeline a 5 fasi). Genera un **corpus di seed
mirati** a partire dallo pseudocodice decompilato e dai finding del
`vuln_scanner`, pronto per essere dato in pasto a una campagna di
fuzzing (AFL++, libFuzzer, o altro).

**Non lancia una vera campagna di fuzzing**: quella richiede WSL2/Linux
(i binari target sono ELF) ed è un passo manuale, da fare con il
framework AFL++ già pronto da un altro progetto. Questo modulo produce
solo il corpus di input — coerente con l'output atteso dallo spec
("Corpus of fuzzing inputs"), ed è **agnostico rispetto al fuzzer**:
è solo una cartella di file, va bene sia per AFL++ (`afl-fuzz -i
seeds/ -o findings/ ...`) sia, con un piccolo adattatore, per
libFuzzer.

## Come funziona

1. **Individuazione delle funzioni di ingresso** (`find_input_functions`):
   scansiona lo pseudocodice cercando le stesse pattern di source
   già usate dalla taint analysis del vuln_scanner (`read`, `recv`,
   `fgets`, `scanf`, `fread`, `argv[...]`, ecc.) — se una funzione è
   una source per la taint analysis, è per definizione anche un punto
   di ingresso rilevante per il fuzzing. Per ogni funzione trovata,
   classifica il tipo di ingresso (`argv`, `file`, `network`,
   `stdin_scanf`) e legge le dimensioni di eventuali buffer locali
   dichiarati nella stessa funzione.

2. **Generazione dei seed** (`generate_seeds_for_function`): per ogni
   funzione di ingresso, genera:
   - un seed "baseline" di 16 byte stampabili;
   - seed di **boundary** attorno a ogni buffer dichiarato nella
     funzione (taglia-1, taglia esatta, taglia+1, taglia×2) — il modo
     più semplice ed efficace per aumentare la probabilità che il
     fuzzer trovi rapidamente un overflow proprio in quel punto;
   - se disponibile `findings_all.json` del vuln_scanner, le taglie
     **esatte già identificate come vulnerabili** per quella funzione
     (es. un finding `BOF_Const_Size_Exceeds_Declared_Buffer` che
     dice "copia 200 byte in un buffer di 16" produce anche un seed
     da 200 byte) — è la nostra implementazione pragmatica del punto
     "Code Coverage Guidance" dello spec: usiamo i finding del
     vuln_scanner al posto del CFG grezzo, perché sono già "il CFG
     interpretato" — i punti che sappiamo essere pericolosi;
   - per le funzioni `stdin_scanf`, anche un seed numerico e uno
     testuale, dato che il formato atteso (`%d` vs `%s`) non è sempre
     deducibile con certezza dal solo pseudocodice.

3. **Priorità via call graph** (`_functions_reaching_targets`, usa
   direttamente `CFG/callgraph_named.graphml` prodotto da
   `angr_cfglib.py` + `relabel_graphs.py`): per ogni funzione già
   segnalata come vulnerabile dal vuln_scanner, calcola con
   `networkx.ancestors()` quali funzioni hanno un cammino di chiamata
   (diretto o transitivo) che arriva fino a lì — cioè quali funzioni
   di ingresso, se fuzzate, hanno concretamente una via per raggiungere
   il codice pericoloso. Le funzioni marcate `cfg_priority`:
   - ricevono seed extra (taglie aggiuntive attorno ai buffer dichiarati);
   - vengono duplicate in `seeds/_priority/`, comodo per puntare lì
     una prima passata di AFL++ prima di allargare a tutto il corpus.

   `networkx` è già una dipendenza del progetto (usata da
   `angr_cfglib.py` e `relabel_graphs.py` per leggere/scrivere gli
   stessi `.graphml`): non serve installare nulla in più. Se il
   callgraph rietichettato non è disponibile (es. `symbols.json`
   mancante, quindi i nomi non combaciano con quelli dello pseudocodice),
   questo passo viene semplicemente saltato — resta un'ottimizzazione,
   non un requisito: il corpus base si genera comunque.

4. **Scrittura del corpus** (`generate_seed_corpus`): un file per
   seed, organizzati in `seeds/<nome_funzione>/<file>`, più
   `seeds/_priority/` per le funzioni che il call graph conferma
   raggiungere codice vulnerabile noto, e un `manifest.json` che
   registra la provenienza (incluso il flag `cfg_priority`) di ogni
   seed — utile per la tesi: si può sempre ricostruire perché un dato
   seed esiste e con quale livello di priorità.

## Limite onesto (da mettere in tesi)

Questo **non** è un vero estrattore di formati/struct come uno
strumento basato su grammatiche o analisi simbolica — è un
generatore euristico basato su pattern testuali sullo pseudocodice
(dimensioni di buffer dichiarate, tipo di sorgente di input, presenza
di format string). Per target con formati di file complessi (parser
binari strutturati, protocolli con campi dipendenti tra loro)
servirebbe un'estrazione più sofisticata — fuori scope per ora,
coerente con la scelta già fatta di concentrarsi sul buffer overflow
per il vuln_scanner.

## Nota sui test case attuali

I tre binari `char_type_overrun_memcpy` in `bins/` **non hanno un
vero punto di ingresso esterno**: la stringa copiata è hardcoded
(`SRC_STR`), non letta da file/stdin/rete/argv. Il generatore trova
correttamente **zero funzioni di ingresso** su questi binari e non
scrive seed — non è un bug, è lo stesso tipo di risultato negativo
spiegabile già documentato per cwe_checker su questa stessa famiglia
di test case. Per validare concretamente la generazione di seed serve
un binario che legga davvero input esterno (es. uno dei target del
progetto FormAI usato per l'esame di penetration testing).

## Uso

Da `pipe.py` (già collegato, gira dopo il vuln_scanner così può
leggerne i finding):

```python
from fuzz_seed_generator.seed_generator import generate_seed_corpus

summary = generate_seed_corpus(
    decompiled_c_path,
    output_dir="risultati/<nome_bin>/fuzzing/seeds",
    findings_all_json="risultati/<nome_bin>/vuln_scanner/findings_all.json",
    callgraph_graphml_path="risultati/<nome_bin>/CFG/callgraph_named.graphml",
)
```

Da CLI, in autonomia:

```bash
python fuzz_seed_generator/seed_generator.py \
    --input risultati/<nome_bin>/decompiled_files/<nome_bin>_decompiled.c \
    --output risultati/<nome_bin>/fuzzing/seeds \
    --findings risultati/<nome_bin>/vuln_scanner/findings_all.json
```

## Passo successivo (manuale, WSL2)

Una volta generato il corpus, la campagna vera si lancia con AFL++
sotto WSL2, riusando il tuo progetto d'esame:

```bash
afl-fuzz -i risultati/<nome_bin>/fuzzing/seeds/<nome_funzione>/ \
         -o risultati/<nome_bin>/fuzzing/findings/ \
         ./<binario_target>
```

Se WSL2 ti da problemi di memoria, limita l'allocazione in
`%USERPROFILE%\.wslconfig`:
```ini
[wsl2]
memory=4GB
processors=2
swap=2GB
```
poi `wsl --shutdown` e riavvia.