"""
report_generator.py
--------------------------------------------------------------------
Reporting Engine (componente 2.5 della pipeline di tesi).

Aggrega quello che le fasi precedenti hanno gia' prodotto per un
binario (finding del vuln_scanner, timing di decompilazione/CFG,
accuracy contro la ground truth se annotata, corpus di seed del
fuzzer se presente) e genera due report:

  - report.html: interattivo, con estratti di codice e suggerimenti
    di remediation (Jinja2, punto 2 dello spec);
  - report.sarif: per l'integrazione con CI/CD (GitHub Code Scanning
    e simili, punto 2 dello spec).

Il fuzzing effettivo (esecuzione della campagna AFL++, confronto
"con seed guidati vs seed casuali") NON e' ancora integrato in
pipe.py (resta una funzione a parte, volutamente disaccoppiata —
vedi PIPELINE_README.md): questo modulo e' gia' pronto ad accoglierlo,
vedi il parametro `fuzzing_effectiveness` di generate_report() e la
sezione dedicata nel template HTML, che restano vuoti finche' quei
dati non esistono.
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

try:
    from .cwe_utils import suggest_remediation
    from .accuracy import load_ground_truth, compute_accuracy
    from .sarif_export import write_sarif
    from .code_context import (
        extract_function_code,
        code_lines_with_highlight,
        find_function_start_line,
        all_lines_numbered,
    )
    from .chart_svg import bar_chart_svg
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from cwe_utils import suggest_remediation
    from accuracy import load_ground_truth, compute_accuracy
    from sarif_export import write_sarif
    from code_context import (
        extract_function_code,
        code_lines_with_highlight,
        find_function_start_line,
        all_lines_numbered,
    )
    from chart_svg import bar_chart_svg

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _cwe_to_url(cwe: str | None) -> str | None:
    """
    Costruisce l'URL della pagina ufficiale MITRE per un identificativo
    CWE (es. "CWE-121" -> https://cwe.mitre.org/data/definitions/121.html),
    estraendo la prima sequenza di cifre trovata cosi' da tollerare
    piccole variazioni di formato ("CWE121", "121", "CWE-121"). Ritorna
    None se non c'e' alcuna cifra da cui costruire un link (nessuna
    chiamata di rete: e' solo una costruzione di stringa, lo schema
    dell'URL e' fisso e pubblico).
    """
    if not cwe:
        return None
    m = re.search(r"\d+", str(cwe))
    return f"https://cwe.mitre.org/data/definitions/{m.group()}.html" if m else None


def _preview_bytes(data: bytes, max_len: int = 200) -> tuple[str, bool]:
    """
    Ritorna (anteprima, is_binary) per il contenuto di un file di seed.
    I seed generati sono spesso stringhe brevi mirate a superare un
    controllo di formato (testo leggibile), ma non e' garantito: se il
    contenuto non decodifica come testo stampabile, mostriamo invece
    un dump esadecimale dei primi byte.
    """
    sample = data[:max_len]
    try:
        text = sample.decode("utf-8")
        if all(c.isprintable() or c in "\n\r\t" for c in text):
            return (text + ("…" if len(data) > max_len else "")), False
    except UnicodeDecodeError:
        pass
    hex_preview = " ".join(f"{b:02x}" for b in sample[:64])
    return (hex_preview + (" …" if len(data) > 64 else "")), True


def _load_seed_manifest_entries(
    manifest_path: str | Path,
    seeds_dir: str | Path | None,
) -> list[dict]:
    """
    Legge manifest.json nello schema reale scritto da
    fuzz_seed_generator: una voce per ogni seed generato, con
    "function", "kind" (es. "network", il tipo di sorgente di input
    individuata), "source_calls" (le chiamate che leggono quell'input,
    es. "recv("), "cfg_priority" (se la funzione e' raggiungibile da
    codice gia' segnalato vulnerabile, via call graph) e "file" (path
    del seed scritto su disco, relativo alla cartella seeds/ - puo'
    contenere backslash se il manifest e' stato scritto su Windows,
    normalizzato qui) e "size" in byte.

    Il manifest da solo non contiene i BYTE del seed, solo i suoi
    metadati: se `seeds_dir` e' fornito, per ogni voce proviamo anche
    a leggere il file indicato da disco per mostrarne un'anteprima nel
    report. Se il file non c'e' (es. la cartella seeds/ non e' stata
    consegnata insieme al manifest), la voce resta comunque nella
    lista, solo senza anteprima - stesso principio "degrada con
    grazia" del resto del modulo.
    """
    raw = _load_json(Path(manifest_path), [])
    entries = []
    for e in raw:
        rel_file = (e.get("file") or "").replace("\\", "/")

        preview, is_binary = None, False
        if seeds_dir and rel_file:
            seed_path = Path(seeds_dir) / rel_file
            if seed_path.is_file():
                try:
                    preview, is_binary = _preview_bytes(seed_path.read_bytes())
                except OSError:
                    pass

        entries.append({
            "function": e.get("function"),
            "kind": e.get("kind"),
            "source_calls": e.get("source_calls") or [],
            "cfg_priority": bool(e.get("cfg_priority")),
            "file": rel_file,
            "file_name": Path(rel_file).name if rel_file else "n/d",
            "size": e.get("size"),
            "preview": preview,
            "is_binary": is_binary,
        })
    return entries


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"[!] {path} non e' JSON valido, ignorato")
        return default


def _load_text_blob(paths: list[str | Path] | str | Path | None) -> str | None:
    """
    Legge uno o piu' file di testo e li concatena in un unico blob su
    cui cercare le funzioni (utile per i testcase Juliet a due file,
    dove la funzione cercata puo' stare nell'uno o nell'altro file).
    Ogni file mancante viene semplicemente saltato con un avviso,
    senza sollevare eccezioni: e' un dato opzionale del report, non
    deve mai farlo fallire.
    """
    if not paths:
        return None
    if isinstance(paths, (str, Path)):
        paths = [paths]

    blobs = []
    for p in paths:
        p = Path(p)
        if not p.exists():
            print(f"[!] File di codice non trovato, ignorato: {p}")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            print(f"[!] Impossibile leggere {p}: {e}")
            continue
        # Se piu' di un file viene concatenato (es. i testcase Juliet a
        # due file "...a.c"/"...b.c"), un separatore col nome del file
        # aiuta a orientarsi nella pagina "file completo" - altrimenti
        # sembrerebbe un unico file senza soluzione di continuita'.
        blobs.append(f"/* ==== {p.name} ==== */\n\n{text}" if len(paths) > 1 else text)

    return "\n\n".join(blobs) if blobs else None


def _as_dict(obj):
    """Normalizza a dict sia i Finding (dataclass) sia i dict gia' pronti."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return obj


def _anchor_line(function_start_line: int | None, snippet_lines: list[dict]) -> int | None:
    """
    Calcola la riga assoluta (nel file completo) a cui deve puntare il
    link "apri nel file completo" di un finding: la riga esatta del
    match se individuata dentro lo snippet della funzione, altrimenti
    l'inizio della funzione stessa. None se la funzione non e' stata
    localizzata affatto (nessun link mostrato in quel caso).
    """
    if function_start_line is None:
        return None
    for i, line in enumerate(snippet_lines):
        if line.get("highlight"):
            return function_start_line + i
    return function_start_line


def _write_full_code_page(
    env: Environment,
    output_dir: Path,
    filename: str,
    binary_name: str,
    title: str,
    code_text: str,
    highlight_set: set[str],
) -> None:
    """
    Scrive una pagina HTML a se stante con l'intero file (decompilato
    o sorgente), numerato riga per riga, con le righe che compaiono
    come matched_line di almeno un finding evidenziate. Serve sia per
    approfondire una debolezza gia' trovata (link dal finding, con
    ancora sulla riga esatta), sia per sfogliare il codice quando
    NESSUN finding e' scattato — capire perche' un motore non ha
    segnalato nulla richiede di poter vedere il codice, non solo un
    "0 finding" in tabella.
    """
    lines = all_lines_numbered(code_text, highlight_set)
    template = env.get_template("full_code.html.jinja2")
    html = template.render(binary_name=binary_name, title=title, lines=lines)
    (output_dir / filename).write_text(html, encoding="utf-8")


def generate_report(
    binary_name: str,
    findings_all_json: str | Path,
    output_dir: str | Path,
    timing: dict | None = None,
    project_root: str | Path | None = None,
    fuzzing_manifest_json: str | Path | None = None,
    fuzzing_effectiveness: list[dict] | None = None,
    decompiled_c_path: str | Path | None = None,
    source_c_paths: list[str | Path] | str | Path | None = None,
    fuzzing_seeds_dir: str | Path | None = None,
) -> dict:
    """
    Genera report.html e report.sarif in output_dir. Ritorna un
    riepilogo (utile per il log della pipeline).

    Tutti i parametri opzionali si degradano con grazia se il file
    corrispondente non esiste (nessuna eccezione, solo una sezione
    "nessun dato disponibile" nel report): il Reporting Engine deve
    produrre un report leggibile anche a pipeline parzialmente
    eseguita, non solo a fine corsa completa.

    decompiled_c_path: path al pseudocodice completo decompilato da
    Ghidra per questo binario (tutte le funzioni in un unico file, il
    tipico output di decompiler.py). Se fornito, per ogni finding con
    un campo "function" valorizzato il report mostra il corpo intero
    di quella funzione invece di un semplice numero di riga (vedi
    reporting/code_context.py per il perche').

    source_c_paths: uno o piu' path al sorgente C originale (piu' di
    uno per i testcase Juliet a file separati, es. "..._51a.c" e
    "..._51b.c"). Se fornito, il report mostra anche il codice
    sorgente della stessa funzione accanto al decompilato, per un
    confronto diretto.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    env.filters["cwe_url"] = _cwe_to_url

    findings_raw = _load_json(Path(findings_all_json), [])
    findings = [_as_dict(f) for f in findings_raw]

    decompiled_text = _load_text_blob(decompiled_c_path)
    source_text = _load_text_blob(source_c_paths)

    # Cache per nome funzione: piu' finding sulla stessa funzione (es.
    # CWE-121 e CWE-126 sullo stesso memcpy) non devono ri-scansionare
    # da capo lo stesso blob di testo per estrarre lo stesso corpo.
    _function_code_cache: dict[str, tuple[str | None, str | None]] = {}
    _function_start_cache: dict[str, tuple[int | None, int | None]] = {}

    for f in findings:
        f["remediation"] = suggest_remediation(f.get("rule"), f.get("cwe"))

        func_name = f.get("function")
        if func_name not in _function_code_cache:
            _function_code_cache[func_name] = (
                extract_function_code(decompiled_text, func_name),
                extract_function_code(source_text, func_name),
            )
            _function_start_cache[func_name] = (
                find_function_start_line(decompiled_text, func_name),
                find_function_start_line(source_text, func_name),
            )
        decompiled_code, source_code = _function_code_cache[func_name]
        decompiled_start, source_start = _function_start_cache[func_name]

        matched_line = f.get("matched_line")
        f["decompiled_lines"] = code_lines_with_highlight(decompiled_code, matched_line)
        f["source_lines"] = code_lines_with_highlight(source_code, matched_line)

        # Ancora verso la riga esatta nella pagina "file completo": se
        # la riga del match e' stata individuata dentro lo snippet,
        # punta a quella; altrimenti (nessun match testuale, es. per un
        # finding di cwe_checker senza matched_line) punta comunque
        # all'inizio della funzione - meglio atterrare li' che non
        # avere nessun link, dato che la funzione e' stata comunque
        # localizzata per nome.
        f["decompiled_anchor"] = _anchor_line(decompiled_start, f["decompiled_lines"])
        f["source_anchor"] = _anchor_line(source_start, f["source_lines"])

    engine_counts: dict[str, int] = {}
    for f in findings:
        engine = f.get("engine", "yara")
        engine_counts[engine] = engine_counts.get(engine, 0) + 1

    engine_chart_svg = bar_chart_svg(engine_counts)

    accuracy_result = None
    if project_root:
        ground_truth = load_ground_truth(project_root)
        accuracy_result = compute_accuracy(binary_name, findings, ground_truth)

    fuzzing_data = None
    if fuzzing_manifest_json and Path(fuzzing_manifest_json).exists():
        seed_entries = _load_seed_manifest_entries(fuzzing_manifest_json, fuzzing_seeds_dir)
        per_function: dict[str, int] = {}
        cfg_priority_functions: set[str] = set()
        for e in seed_entries:
            if e["function"]:
                per_function[e["function"]] = per_function.get(e["function"], 0) + 1
                if e["cfg_priority"]:
                    cfg_priority_functions.add(e["function"])
        fuzzing_data = {
            "per_function": per_function,
            "cfg_priority_functions": cfg_priority_functions,
            "effectiveness": fuzzing_effectiveness,
            "seed_entries": seed_entries,
        }

    # Pagine "file completo": indipendenti dai singoli finding, quindi
    # generate anche se non c'e' NESSUN finding per questo binario -
    # e' proprio nel caso "0 finding" che poter sfogliare il codice
    # (per capire se e' un vero negativo o un buco del motore) e' piu'
    # utile. Le righe che coincidono con un matched_line di qualunque
    # finding vengono evidenziate anche qui, cosi' il file intero da'
    # un colpo d'occhio su dove sono stati tutti i match.
    matched_lines_global = {
        f["matched_line"].strip() for f in findings if f.get("matched_line")
    }

    decompiled_page_url = None
    if decompiled_text:
        _write_full_code_page(
            env, output_dir, "decompiled.html", binary_name,
            "Decompilato completo (Ghidra)", decompiled_text, matched_lines_global,
        )
        decompiled_page_url = "decompiled.html"

    source_page_url = None
    if source_text:
        _write_full_code_page(
            env, output_dir, "source.html", binary_name,
            "Sorgente completo", source_text, matched_lines_global,
        )
        source_page_url = "source.html"

    template = env.get_template("report.html.jinja2")
    html = template.render(
        binary_name=binary_name,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        findings=findings,
        engine_counts=engine_counts,
        engine_chart_svg=engine_chart_svg,
        timing=timing,
        accuracy=accuracy_result,
        fuzzing=fuzzing_data,
        decompiled_page_url=decompiled_page_url,
        source_page_url=source_page_url,
    )
    (output_dir / "report.html").write_text(html, encoding="utf-8")

    write_sarif(findings, binary_name, output_dir / "report.sarif")

    summary = {
        "binary": binary_name,
        "findings_total": len(findings),
        "engine_counts": engine_counts,
        "accuracy_available": accuracy_result.has_ground_truth if accuracy_result else False,
    }
    if accuracy_result and accuracy_result.has_ground_truth:
        summary["true_positive_rate"] = accuracy_result.true_positive_rate
        summary["false_positives"] = accuracy_result.false_positive_count

    return summary


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Reporting Engine - genera report.html + report.sarif")
    parser.add_argument("--binary", required=True, help="Nome del binario (per il titolo del report e la ground truth)")
    parser.add_argument("--findings", required=True, help="Path a findings_all.json")
    parser.add_argument("--output", required=True, help="Cartella di output per report.html / report.sarif")
    parser.add_argument("--timing", default=None, help="Path a timing.json (opzionale)")
    parser.add_argument("--project-root", default=None, help="Root del progetto, per trovare ground_truth.json (opzionale)")
    parser.add_argument("--fuzzing-manifest", default=None, help="Path a manifest.json del fuzz_seed_generator (opzionale)")
    parser.add_argument("--decompiled", default=None, help="Path al pseudocodice completo decompilato da Ghidra (opzionale)")
    parser.add_argument("--source", action="append", default=None,
                         help="Path a un sorgente C originale; ripetibile per i testcase Juliet a piu' file (opzionale)")
    args = parser.parse_args()

    timing_data = _load_json(Path(args.timing), None) if args.timing else None

    summary = generate_report(
        args.binary,
        args.findings,
        args.output,
        timing_data,
        args.project_root,
        args.fuzzing_manifest,
        decompiled_c_path=args.decompiled,
        source_c_paths=args.source,
    )
    print(f"[+] Report generato in {args.output}: {summary}")