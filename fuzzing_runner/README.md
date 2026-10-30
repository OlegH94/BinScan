# fuzzing_runner — Esecuzione vera del fuzzing (AFL++)

Componente lasciato volutamente "a parte" per tutta la durata del
progetto (vedi PIPELINE_README.md): due campagne AFL++ per ogni
binario fuzzabile, una con i seed generati da `fuzz_seed_generator`,
una con un seed banale generico — per confrontarne l'efficacia.

## Perché Docker invece di AFL++ nativo in WSL2

`afl-fuzz -Q` (QEMU mode, necessario per fuzzare binari già compilati
senza instrumentazione) richiede il binario `afl-qemu-trace`, che
**non è incluso** in molte installazioni pacchettizzate (verificato:
assente su Kali via apt) — va compilato a parte, un processo
storicamente fragile (dipendenze `glib`/`pixman`, patch).

L'immagine Docker ufficiale (`aflplusplus/aflplusplus`) lo include già
compilato e pronto (`/usr/local/bin/afl-qemu-trace`, verificato
presente). Stesso pattern già usato in questo progetto per
`cwe_checker_integration.py` — `docker run --rm -v ...` — qui applicato
a questa immagine invece che a quella di cwe_checker.

## Scope dichiarato (v1) — non tutti i tipi di ingresso sono fuzzabili qui

`fuzz_seed_generator` classifica ogni funzione di ingresso trovata in
uno di quattro tipi. Questo modulo ne supporta solo due:

| Tipo | Supportato | Perché |
|---|---|---|
| `stdin_scanf` | ✅ | AFL++ fuzza stdin di default |
| `file` | ✅ | AFL++ sostituisce `@@` con un path a un file generato |
| `argv` | ❌ | Il modello `@@` di AFL fuzza il *contenuto* di un file, non il *valore letterale* di un argomento — i due non sono equivalenti; servirebbe un harness dedicato |
| `network` | ❌ | Il programma legge da un vero socket TCP (`recv()`), non da stdin — servirebbe un wrapper come `desock`/`preeny` per reindirizzare le chiamate di rete a stdin, non incluso qui |

I binari con tipo non supportato vengono **saltati con un log esplicito**
del motivo, non con un errore silenzioso.

## ⚠️ Cosa è stato verificato e cosa no

Questo modulo è stato scritto e testato **solo nella sua logica
Python pura** — l'ambiente di sviluppo non ha accesso a Docker:

- ✅ **Verificato**: selezione dei binari fuzzabili (filtro per tipo
  di ingresso), raccolta/appiattimento dei seed generati, parsing di
  `fuzzer_stats` (entrambi i formati di chiave, vecchio e nuovo stile
  AFL++), costruzione della tabella di confronto, integrazione con
  `generate_report()` (chiamato con gli argomenti corretti).
- ❓ **Da verificare nel tuo ambiente reale**: che il comando `docker
  run` costruito funzioni esattamente come scritto contro l'immagine
  vera — nomi delle variabili d'ambiente (`AFL_NO_UI`,
  `AFL_SKIP_CPUFREQ`, `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`, comuni
  in molte guide AFL++-in-container ma non testate qui direttamente),
  formato esatto di `fuzzer_stats` per la tua versione specifica di
  AFL++, comportamento reale di QEMU mode sui binari ELF Juliet.

Se la prima campagna reale fallisce con un errore di avvio (non un
crash del target, proprio AFL++ che si rifiuta di partire), guarda
prima queste tre variabili d'ambiente — è il punto più comune di
attrito nel far girare AFL++ dentro un container.

## Struttura

```
fuzzing_runner/
├── README.md
└── fuzzing_runner.py   # discover_fuzzable_binaries, run_campaign, parse_fuzzer_stats, build_comparison
```

Più `run_fuzzing_campaigns.py` nella root del progetto (script di
orchestrazione, stesso stile di `rerun_scanning.py`/`run_llm_review.py`).

## Output, per ogni binario fuzzato

```
risultati/<nome_bin>/fuzzing/
├── seeds/                        # già esistente, da fuzz_seed_generator
├── campaign_with_seeds/          # output grezzo di AFL++ (crash, hang, coda)
├── campaign_without_seeds/
└── comparison.json               # confronto strutturato con/senza seed
```

Il `report.html` del binario viene **rigenerato** (non richiama
Ghidra/vuln_scanner) con la sezione "Fuzzing" ora popolata — quella
sezione esisteva già nel template, vuota, in attesa proprio di questi
dati.

## Uso

```bash
python run_fuzzing_campaigns.py                      # tutti i binari fuzzabili trovati
python run_fuzzing_campaigns.py --only NOME_BIN       # solo uno, per la prima prova
python run_fuzzing_campaigns.py --duration 300        # 5 minuti a campagna invece del default (120s)
```

**Consiglio**: la prima volta, usa `--only` su un singolo binario con
una durata breve (es. `--duration 60`) per verificare che il
meccanismo Docker/QEMU funzioni davvero nel tuo ambiente, prima di
lanciare campagne più lunghe su tutto il batch — ogni binario richiede
`2 × durata` (due campagne sequenziali), quindi il tempo totale sale
in fretta con molti binari.

## Limiti onesti aggiuntivi (da mettere in tesi)

- **QEMU mode è più lento** dell'instrumentazione nativa a tempo di
  compilazione (nessun binario Juliet in questo progetto è stato
  ricompilato con `afl-gcc`/`afl-clang-fast`) — il confronto con/senza
  seed resta valido, ma i numeri assoluti di velocità di esecuzione
  non sono comparabili con setup che usano instrumentazione nativa.
- **"Senza seed" è un seed minimo, non zero seed**: AFL++ richiede
  sempre almeno un test case di partenza; il confronto è quindi "seed
  mirati" vs "seed generico banale", non "input" vs "nessun input".
- **Durata breve per la prima validazione**: 120 secondi di fuzzing
  raramente basta a AFL++ per esplorare a fondo lo spazio degli input,
  specialmente in QEMU mode (più lento). Per risultati significativi
  su cui basare conclusioni nella tesi, considera campagne più lunghe
  (10-30 minuti) su un sottoinsieme scelto di binari, invece di tempi
  brevi su tutti.