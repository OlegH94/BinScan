"""
llm_review.py
--------------------------------------------------------------------
Quarto motore di revisione, VOLUTAMENTE separato dai tre principali
(vuln_scanner/scanner.py, semgrep_scanner.py, cwe_checker_integration.py):
non produce finding nello stesso findings_all.json, scrive in una
cartella propria (llm_review/) con un report proprio.

Un giudizio LLM e' probabilistico, non una prova deterministica come
pattern matching (YARA), parsing AST (semgrep), o interpretazione
astratta (cwe_checker) — per questo resta una fonte di evidenza
separata invece di essere mescolato ai tre motori "principali"
nell'accuracy testing. Va citato come categoria distinta in tesi.

Tre criteri di selezione delle funzioni da rivedere, applicati insieme:
1. Conferma sui candidati gia' segnalati da YARA/semgrep/cwe_checker
   per quella funzione (gli passiamo il contesto di chi ha segnalato
   cosa, e chiediamo se e' plausibile o probabile falso positivo).
2. SE il call graph (CFG/callgraph_named.graphml, stesso file gia'
   usato da fuzz_seed_generator) e' disponibile: funzioni davvero
   RAGGIUNGIBILI da main() nel programma reale, non solo definite nel
   file — esclude gli stub morti mai chiamati (nei binari Juliet:
   good1()..good9()/bad1()..bad9() quando si compila solo "-bad").
   Generalizza oltre la convenzione Juliet: funziona su QUALSIASI
   binario, non solo su questo dataset sintetico.
3. ALTRIMENTI (callgraph mancante o senza nodo "main" riconoscibile):
   analizza semplicemente main() stesso, come seconda opinione
   indipendente — nessuna convenzione di naming specifica del
   dataset: su un binario reale non esiste un equivalente di "_bad",
   main() e' l'unica funzione che sappiamo per certo esistere ed
   essere il punto di ingresso, senza bisogno di alcuna convenzione.

Il criterio 2/3 attacca esattamente i casi gia' diagnosticati dove il
compilatore elimina la chiamata a funzione (memmove sostituita da
costanti, memcpy srotolata in scritture dirette via puntatore): un
pattern che nessuno dei tre motori a regole/pattern puo' vedere per
costruzione, ma che un modello che "legge" il codice puo' notare —
anche quando NESSUN motore ha segnalato nulla per quella funzione.

Richiede Ollama in esecuzione in locale (https://ollama.com):
    ollama pull qwen2.5-coder:7b
    ollama serve   (di solito parte gia' in background dopo l'installazione)

Uso da libreria:
    from llm_reviewer.llm_review import review_binary
    review_binary(decompiled_c_path, findings_all_json, output_dir,
                   callgraph_path="risultati/<nome_bin>/CFG/callgraph_named.graphml")
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

try:
    from .prompts import build_review_prompt
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from prompts import build_review_prompt

OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b"
_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Stessa firma di funzione usata nel resto del progetto (scanner.py,
# fuzz_seed_generator/seed_generator.py) — duplicata qui apposta per
# tenere questo modulo utilizzabile anche senza vuln_scanner presente,
# coerente con la stessa scelta gia' fatta per fuzz_seed_generator.
_FUNC_SIGNATURE_RE = re.compile(r"^[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*\{", re.MULTILINE)

# Lista di riserva (fast-path, non l'unico controllo): tenuta per le
# funzioni piu' comuni, ma NON e' piu' il controllo primario — vedi
# _STUB_CALL_RE sotto. Una lista fissa di nomi perde sempre qualcosa
# (es. "htons" per i binari con socket, mai anticipato qui) e va
# aggiornata all'infinito man mano che compaiono binari diversi.
_KNOWN_LIBRARY_FUNCTIONS = {
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf", "gets", "fgets",
    "scanf", "sscanf", "fscanf", "__isoc99_scanf", "__isoc99_sscanf",
    "printf", "fprintf", "read", "recv", "recvfrom", "fread", "alloca",
    "malloc", "calloc", "realloc", "free", "strlen", "strnlen", "getenv",
    "puts", "time", "srand", "rand", "exit", "abort",
}

# Riconoscimento STRUTTURALE (non per nome) degli stub che Ghidra genera
# per OGNI funzione di libreria risolta via PLT/GOT, qualunque sia il
# nome — verificato su tutti i decompiled.c visti finora (puts, printf,
# memcpy, srand, time, wprintf, rand, __ctype_b_loc, iswxdigit, ...):
# il corpo contiene sempre la stessa identica forma
# "(*(code *)PTR_<nome>_<indirizzo>)()". Molto piu' robusto della lista
# fissa sopra: copre automaticamente QUALSIASI funzione di libreria
# (rete, matematica, stringhe, ecc.) senza doverla enumerare a mano.
_STUB_CALL_RE = re.compile(r"\(\*\s*\(code\s*\*\)\s*PTR_")

# Seconda forma di "non-codice" vista nei decompiled.c: le ridefinizioni
# duplicate delle stesse funzioni di libreria verso la fine del file,
# con corpo tronco per istruzioni non valide — anche queste non sono
# mai codice del programma da rivedere.
_HALT_BADDATA_RE = re.compile(r"\bhalt_baddata\s*\(")


class OllamaNotAvailable(RuntimeError):
    """Ollama non e' raggiungibile su localhost:11434."""


def _check_ollama_available(base_url: str = OLLAMA_BASE_URL) -> None:
    try:
        req = urllib.request.Request(f"{base_url}/api/tags")
        urllib.request.urlopen(req, timeout=5)
    except (urllib.error.URLError, ConnectionError) as e:
        raise OllamaNotAvailable(
            f"Ollama non raggiungibile su {base_url}. Installa da https://ollama.com, "
            f"poi 'ollama pull {DEFAULT_MODEL}' e assicurati che sia in esecuzione."
        ) from e


def _split_into_functions(source_text: str) -> list[tuple[str, str]]:
    matches = list(_FUNC_SIGNATURE_RE.finditer(source_text))
    if not matches:
        return [("<intero_file>", source_text)]
    out = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source_text)
        name = m.group(1)
        body = source_text[start:end]
        if name in _KNOWN_LIBRARY_FUNCTIONS:
            continue
        if _STUB_CALL_RE.search(body) or _HALT_BADDATA_RE.search(body):
            continue
        out.append((name, body))
    return out


def _functions_reachable_from_main(callgraph_path: str | Path) -> set[str] | None:
    """
    Usa CFG/callgraph_named.graphml (stesso file e stessa tecnica gia'
    usata in fuzz_seed_generator per la priorita' via call graph) per
    trovare tutte le funzioni RAGGIUNGIBILI da main() nel programma
    reale — non solo le funzioni definite nello pseudocodice, che
    include anche stub morti mai chiamati (nei binari Juliet: le
    funzioni good1()..good9()/bad1()..bad9(), definite ma non usate
    quando si compila solo la variante "-bad").

    E' una generalizzazione dell'alternativa piu' semplice (analizzare
    solo main()): la raggiungibilita' dal main funziona su QUALSIASI
    binario, non solo su questo dataset sintetico.

    Ritorna None (invece di un set vuoto) se il callgraph non e'
    disponibile o non contiene un nodo "main" — il chiamante deve
    allora ricadere sulla convenzione di naming come prima, non
    trattare "nessuna funzione raggiungibile trovata" come se
    davvero non ci fosse nulla da rivedere.
    """
    path = Path(callgraph_path)
    if not path.exists():
        return None

    try:
        import networkx as nx  # gia' dipendenza del progetto (angr_cfglib.py, relabel_graphs.py, seed_generator.py)
    except ImportError:
        return None

    try:
        graph = nx.read_graphml(str(path))
    except Exception:
        return None

    main_node = None
    for node_id, data in graph.nodes(data=True):
        if data.get("name") == "main":
            main_node = node_id
            break

    if main_node is None:
        return None

    node_to_name = {n: d.get("name") for n, d in graph.nodes(data=True)}
    reachable = {node_to_name[main_node]}
    try:
        reachable.update(node_to_name[n] for n in nx.descendants(graph, main_node) if node_to_name.get(n))
    except Exception:
        pass

    return reachable


class OllamaTimeout(RuntimeError):
    """Ollama non ha risposto entro il timeout (es. modello ancora in caricamento a freddo su CPU)."""


def _call_ollama(prompt: str, model: str = DEFAULT_MODEL, base_url: str = OLLAMA_BASE_URL, timeout: int = 300) -> str:
    """
    timeout di default alzato a 300s (5 minuti): al primo utilizzo
    Ollama deve caricare il modello (alcuni GB) in RAM prima di poter
    generare qualunque risposta — su CPU pura, senza GPU, questo
    caricamento a freddo puo' da solo superare abbondantemente 120s,
    prima ancora di iniziare a generare (osservato: socket.timeout
    con 120s su una richiesta partita subito dopo l'avvio di Ollama).
    Le chiamate successive nello stesso batch sono piu' veloci perche'
    il modello resta caricato in memoria tra una richiesta e l'altra.
    """
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.1},
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (TimeoutError, OSError) as e:
        # urllib.error.URLError e socket.timeout ereditano entrambi da
        # OSError: catturarlo qui invece di lasciarlo propagare grezzo
        # evita che UN SOLO timeout faccia fallire l'intero batch —
        # stessa filosofia gia' applicata a semgrep/cwe_checker.
        raise OllamaTimeout(
            f"Ollama non ha risposto entro {timeout}s (probabile caricamento a freddo del modello "
            f"su CPU, specialmente alla prima chiamata della sessione)."
        ) from e

    return body.get("response", "")


def _parse_llm_json(raw_response: str) -> dict:
    """
    Anche con format="json" un modello puo' aggiungere testo prima/dopo
    il JSON vero e proprio: estraiamo il primo blocco {...} valido
    invece di fidarci ciecamente che la risposta sia SOLO JSON.
    """
    try:
        return json.loads(raw_response)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", raw_response, re.S)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return {
        "vulnerable": None,
        "cwe": None,
        "confidence": "low",
        "explanation": f"Risposta del modello non interpretabile come JSON: {raw_response[:200]}",
        "parse_error": True,
    }


@dataclass
class ReviewEntry:
    function: str
    file: str
    reviewed_because: str  # "flagged_by_other_engine" | "reachable_from_main" | "main_entry_point"
    other_engine_findings: list[dict] = field(default_factory=list)
    vulnerable: bool | None = None
    cwe: str | None = None
    confidence: str = "low"
    explanation: str = ""
    parse_error: bool = False


def _select_functions_to_review(
    source_text: str,
    findings_all: list[dict],
    reachable_from_main: set[str] | None = None,
) -> list[tuple[str, str, str, list[dict]]]:
    """
    Ritorna [(nome_funzione, testo_funzione, motivo, finding_altri_motori)].

    Criteri, applicati in ordine di preferenza (una funzione puo'
    comparire per piu' di uno, in tal caso vince quello con piu'
    contesto da passare al modello):
      1. funzioni gia' segnalate da almeno un finding in findings_all
         -> motivo "flagged_by_other_engine"
      2. SE reachable_from_main e' fornito (callgraph disponibile CON
         un nodo main riconosciuto): funzioni davvero raggiungibili da
         main() -> motivo "reachable_from_main"
      3. ALTRIMENTI (reachable_from_main is None, callgraph mancante o
         senza nodo main): fallback su main() stesso -> motivo
         "main_entry_point". Deliberatamente NON usiamo piu' una
         convenzione di naming specifica del dataset (es. "_bad" nei
         binari Juliet): su un binario reale non esiste un equivalente,
         e sfruttare quella convenzione qui sarebbe un vantaggio che
         nella pratica non si ha mai. main() e' l'unica funzione che
         sappiamo per certo esistere ed essere il punto di ingresso,
         senza bisogno di alcuna convenzione — meno mirato del
         criterio 2, ma onesto.
    """
    functions = _split_into_functions(source_text)
    findings_by_function: dict[str, list[dict]] = {}
    for f in findings_all:
        func = f.get("function")
        if func:
            findings_by_function.setdefault(func, []).append(f)

    selected = []
    for func_name, func_text in functions:
        own_findings = findings_by_function.get(func_name, [])
        if own_findings:
            selected.append((func_name, func_text, "flagged_by_other_engine", own_findings))
        elif reachable_from_main is not None:
            if func_name in reachable_from_main:
                selected.append((func_name, func_text, "reachable_from_main", []))
        elif func_name == "main":
            selected.append((func_name, func_text, "main_entry_point", []))

    return selected


def review_binary(
    decompiled_c_path: str | Path,
    findings_all_json: str | Path | None,
    output_dir: str | Path,
    model: str = DEFAULT_MODEL,
    base_url: str = OLLAMA_BASE_URL,
    callgraph_path: str | Path | None = None,
) -> list[ReviewEntry]:
    """
    Entry point principale. Scrive review.json e review.html in
    output_dir. Solleva OllamaNotAvailable se Ollama non risponde:
    e' compito del chiamante (uno script a parte, non pipe.py — questo
    modulo resta volutamente disaccoppiato) decidere se bloccare o
    loggare e saltare.

    callgraph_path: CFG/callgraph_named.graphml prodotto dalla fase
    CFG della pipeline (stesso file usato da fuzz_seed_generator).
    Se assente o senza un nodo "main" riconoscibile, la selezione
    delle funzioni ricade sull'analisi di main() stesso
    (vedi _select_functions_to_review) — nessun errore, solo una
    selezione meno precisa.
    """
    _check_ollama_available(base_url)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    source_text = Path(decompiled_c_path).read_text(encoding="utf-8", errors="ignore")

    findings_all: list[dict] = []
    if findings_all_json and Path(findings_all_json).exists():
        try:
            findings_all = json.loads(Path(findings_all_json).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    reachable_from_main = _functions_reachable_from_main(callgraph_path) if callgraph_path else None

    to_review = _select_functions_to_review(source_text, findings_all, reachable_from_main)

    entries: list[ReviewEntry] = []
    for func_name, func_text, reason, own_findings in to_review:
        prompt = build_review_prompt(func_name, func_text, own_findings)

        print(f"[*] Chiamata a Ollama per '{func_name}' in corso... "
              f"(fino a qualche minuto alla prima chiamata della sessione, il modello deve caricarsi)", flush=True)

        try:
            raw_response = _call_ollama(prompt, model=model, base_url=base_url)
            parsed = _parse_llm_json(raw_response)
        except OllamaTimeout as e:
            print(f"[!] {func_name}: {e} — salto questa funzione e proseguo", flush=True)
            parsed = {
                "vulnerable": None,
                "cwe": None,
                "confidence": "low",
                "explanation": f"Timeout durante la revisione: {e}",
                "parse_error": True,
            }

        entries.append(
            ReviewEntry(
                function=func_name,
                file=Path(decompiled_c_path).name,
                reviewed_because=reason,
                other_engine_findings=own_findings,
                vulnerable=parsed.get("vulnerable"),
                cwe=parsed.get("cwe"),
                confidence=parsed.get("confidence", "low"),
                explanation=parsed.get("explanation", ""),
                parse_error=parsed.get("parse_error", False),
            )
        )

    (output_dir / "review.json").write_text(
        json.dumps([asdict(e) for e in entries], indent=2, ensure_ascii=False), encoding="utf-8"
    )

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("review.html.jinja2")
    html = template.render(entries=entries, model=model, binary_name=Path(decompiled_c_path).stem)
    (output_dir / "review.html").write_text(html, encoding="utf-8")

    return entries


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Revisione LLM (Ollama locale) su pseudocodice decompilato")
    parser.add_argument("--decompiled", required=True, help="Path al file .c decompilato")
    parser.add_argument("--findings", default=None, help="Path a findings_all.json (opzionale)")
    parser.add_argument("--output", required=True, help="Cartella di output (llm_review/)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Nome modello Ollama (default: {DEFAULT_MODEL})")
    parser.add_argument("--callgraph", default=None, help="Path a CFG/callgraph_named.graphml (opzionale, generalizza oltre la convenzione '_bad')")
    args = parser.parse_args()

    entries = review_binary(args.decompiled, args.findings, args.output, model=args.model, callgraph_path=args.callgraph)
    print(f"[+] {len(entries)} funzioni revisionate -> {args.output}")
    for e in entries:
        verdict = "VULNERABILE" if e.vulnerable else ("non vulnerabile" if e.vulnerable is False else "incerto")
        print(f"    - {e.function} ({e.reviewed_because}): {verdict}, {e.cwe or 'nessun CWE'}, confidenza {e.confidence}")