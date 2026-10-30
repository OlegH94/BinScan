"""
pipe.py
--------------------------------------------------------------------
Orchestratore della pipeline di tesi. Sostituisce la logica che era
in main.py: ora main.py si limita a chiamare run_all() da qui.

Cosa fa:
  1. Scandisce bins/ e per ogni binario crea risultati/<nome_bin>/
     con una sottocartella per ogni fase (bin, unpacked, decompiled,
     CFG, vuln_scanner, fuzzing, reporting).
  2. Copia il binario originale in risultati/<nome_bin>/bin/, cosi'
     ogni binario da analizzare e' autocontenuto nella sua cartella
     risultati (utile per angr/Ghidra, che a volte modificano o
     bloccano il file mentre lo analizzano).
  3. Esegue le fasi in sequenza: unpack -> decompile -> CFG (+relabel)
     -> vuln_scanner. Fuzzing e reporting sono placeholder per ora
     (li integriamo dopo, vedi TODO in fondo al file).
  4. Espone reset_binary_results()/reset_all_results() per rifare un
     esperimento da zero senza lasciare file vecchi in giro.

Uso da CLI:
    python pipe.py                      # esegue la pipeline su tutti i binari in bins/
    python pipe.py --only NOME_BIN      # esegue solo su un binario
    python pipe.py --list               # elenca i binari trovati in bins/
    python pipe.py --reset NOME_BIN     # cancella risultati/<NOME_BIN>/
    python pipe.py --reset-all          # cancella tutta risultati/
    python pipe.py --redo NOME_BIN      # reset + riesegue quel binario
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
import traceback
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path

import decompiler.decompiler as de
import decompiler.unipack as unp
import angr_cfglib as an
from relabel_graphs import load_symbols, relabel_callgraph, relabel_global_cfg
from vuln_scanner.scanner import run_scan as run_vuln_scan
from vuln_scanner.semgrep_scanner import run_semgrep_scan, SemgrepNotAvailable
from vuln_scanner.cwe_checker_integration import run_cwe_checker, CweCheckerNotAvailable
from fuzz_seed_generator.seed_generator import generate_seed_corpus
from reporting.report_generator import generate_report
from reporting.juliet_ground_truth_importer import (
    build_ground_truth_from_manifest,
    merge_into_existing,
    resolve_source_paths,
)
from reporting.aggregate_report import generate_aggregate_report

BINS_DIR = Path("bins")
RISULTATI_DIR = Path("risultati")
SOURCES_DIR = Path("sources")
JULIET_MANIFEST_PATH = SOURCES_DIR / "manifest.xml"
GROUND_TRUTH_PATH = Path("ground_truth.json")

CFG_MODE = "fast"  # "fast" o "accurate", vedi angr_cfglib.CFGAnalyzer


# ============================================================================
# LAYOUT CARTELLE PER-BINARIO
# ============================================================================

@dataclass
class BinaryPaths:
    """Tutti i path di lavoro per UN binario, dentro risultati/<nome>/."""
    name: str
    root: Path
    bin_dir: Path            # risultati/<nome>/bin/
    bin_path: Path           # risultati/<nome>/bin/<nome>  (copia del binario originale)
    unpacked_dir: Path       # risultati/<nome>/unpacked/
    decompiled_dir: Path     # risultati/<nome>/decompiled_files/ (nome fisso, vedi decompiler.py)
    cfg_dir: Path            # risultati/<nome>/CFG/
    vuln_scanner_dir: Path   # risultati/<nome>/vuln_scanner/
    fuzzing_dir: Path        # risultati/<nome>/fuzzing/            (placeholder)
    reporting_dir: Path      # risultati/<nome>/reporting/          (placeholder)


def get_binary_paths(binary_name: str, risultati_dir: Path = RISULTATI_DIR) -> BinaryPaths:
    """
    Calcola (e crea) la struttura di cartelle per un binario. Puo'
    essere chiamata piu' volte senza effetti collaterali: mkdir e'
    idempotente (exist_ok=True).
    """
    root = risultati_dir / binary_name

    paths = BinaryPaths(
        name=binary_name,
        root=root,
        bin_dir=root / "bin",
        bin_path=root / "bin" / binary_name,
        unpacked_dir=root / "unpacked",
        # NB: il nome "decompiled_files" e' quello scritto (hardcoded)
        # da DecompScript.java dentro alla cwd che gli passiamo
        # (root stessa) — vedi decompiler.decompile(). Se un giorno
        # cambiate quel nome nel .java, aggiornatelo anche qui.
        decompiled_dir=root / "decompiled_files",
        cfg_dir=root / "CFG",
        vuln_scanner_dir=root / "vuln_scanner",
        fuzzing_dir=root / "fuzzing",
        reporting_dir=root / "reporting",
    )

    for d in (paths.bin_dir, paths.unpacked_dir, paths.cfg_dir,
              paths.vuln_scanner_dir, paths.fuzzing_dir, paths.reporting_dir):
        d.mkdir(parents=True, exist_ok=True)

    return paths


def discover_binaries(bins_dir: Path = BINS_DIR) -> list[Path]:
    """Elenca i file (non le sottocartelle, non i file nascosti) in bins/."""
    if not bins_dir.exists():
        print(f"[!] Cartella bins/ non trovata: {bins_dir}")
        return []
    return sorted(
        p for p in bins_dir.iterdir()
        if p.is_file() and not p.name.startswith(".")
    )


# ============================================================================
# RESET (per rifare un esperimento)
# ============================================================================

def reset_binary_results(binary_name: str, risultati_dir: Path = RISULTATI_DIR) -> bool:
    """Cancella risultati/<binary_name>/ per rieseguire la pipeline da zero su quel binario."""
    root = risultati_dir / binary_name
    if root.exists():
        shutil.rmtree(root)
        print(f"[+] Cancellato: {root}")
        return True
    print(f"[=] Nessun risultato da cancellare per: {binary_name}")
    return False


def reset_all_results(risultati_dir: Path = RISULTATI_DIR) -> None:
    """Cancella TUTTA la cartella risultati/ (tutti i binari)."""
    if risultati_dir.exists():
        shutil.rmtree(risultati_dir)
        print(f"[+] Cancellato: {risultati_dir}")
    risultati_dir.mkdir(parents=True, exist_ok=True)


# ============================================================================
# FASI DELLA PIPELINE
# ============================================================================

def _copy_binary(binary_path: Path, paths: BinaryPaths) -> Path:
    shutil.copy2(binary_path, paths.bin_path)
    print(f"[+] Binario copiato in: {paths.bin_path}")
    return paths.bin_path


def _phase_unpack(paths: BinaryPaths) -> Path:
    """
    Ritorna il path del binario da usare nelle fasi successive: quello
    unpacked se e' stato rilevato packing, altrimenti la copia originale.
    """
    unpacked_target = paths.unpacked_dir / paths.name
    was_unpacked = unp.smart_unpack_pipeline(str(paths.bin_path), str(unpacked_target))
    if was_unpacked and unpacked_target.exists():
        print(f"[+] Uso versione unpacked: {unpacked_target}")
        return unpacked_target
    return paths.bin_path


def _phase_decompile(target_path: Path, paths: BinaryPaths):
    decompiled_c, symbols_json = de.decompile(target_path, output_dir=paths.root)
    return decompiled_c, symbols_json


def _phase_cfg(target_path: Path, symbols_json, paths: BinaryPaths):
    analyzer = an.CFGAnalyzer(str(target_path), cfg_mode=CFG_MODE)
    an.export_cfg(analyzer, str(paths.cfg_dir))

    if symbols_json:
        symbols = load_symbols(str(symbols_json))
        print(f"[*] Simboli Ghidra caricati: {len(symbols)}")
        relabel_callgraph(
            str(paths.cfg_dir / "callgraph.graphml"),
            symbols,
            str(paths.cfg_dir / "callgraph_named.graphml"),
        )
        relabel_global_cfg(
            str(paths.cfg_dir / "cfg_global.graphml"),
            symbols,
            str(paths.cfg_dir / "cfg_global_named.graphml"),
        )
    else:
        print("[!] Nessun symbols.json: i grafi restano con nomi sub_XXXX")

    return analyzer


def _phase_vuln_scanner(decompiled_c, symbols_json, target_path, paths: BinaryPaths) -> dict:
    """
    Esegue i tre motori di scansione IN PARALLELO (nessuno sostituisce
    gli altri): YARA+taint custom (scanner.py), semgrep con regole
    equivalenti + taint mode nativo (semgrep_scanner.py), e cwe_checker
    via Docker sul binario stesso (cwe_checker_integration.py, il
    sostituto di BinAbsInspector). Ognuno e' opzionale: se manca la
    dipendenza (semgrep non installato, Docker non disponibile) la
    fase si logga e si salta senza bloccare la pipeline.

    Ritorna un dict {"yara": [...], "semgrep": [...], "cwe_checker": [...]}
    (solo le chiavi delle fasi effettivamente eseguite) e scrive anche
    un findings_all.json con tutto unito, taggato per "engine".
    """
    results: dict[str, list] = {}

    if decompiled_c:
        yara_findings = run_vuln_scan(decompiled_c, paths.vuln_scanner_dir / "findings_yara.json")
        results["yara"] = yara_findings
        print(f"[+] YARA+taint: {len(yara_findings)} finding")

        try:
            semgrep_findings = run_semgrep_scan(decompiled_c, paths.vuln_scanner_dir / "findings_semgrep.json")
            results["semgrep"] = semgrep_findings
            print(f"[+] semgrep: {len(semgrep_findings)} finding")
        except SemgrepNotAvailable as e:
            print(f"[!] semgrep saltato: {e}")
    else:
        print("[!] YARA/semgrep saltati: nessuno pseudocodice decompilato disponibile")

    try:
        cwe_checker_findings = run_cwe_checker(
            target_path,
            paths.vuln_scanner_dir / "findings_cwe_checker.json",
            symbols_json=symbols_json,
        )
        results["cwe_checker"] = cwe_checker_findings
        print(f"[+] cwe_checker: {len(cwe_checker_findings)} finding")
    except CweCheckerNotAvailable as e:
        print(f"[!] cwe_checker saltato: {e}")

    # findings_all.json: unione di tutto, ciascuno gia' taggato "engine"
    # dal proprio wrapper -> comodo input unico per il Reporting Engine.
    # I finding YARA sono oggetti Finding (dataclass), quelli di
    # semgrep/cwe_checker sono gia' dict: normalizziamo tutto a dict
    # prima di unire, altrimenti json.dumps(default=str) serializza i
    # Finding come stringa grezza ("Finding(rule=..., ...)") invece
    # che come oggetto JSON strutturato, rendendoli invisibili a
    # chiunque parsi il file cercando oggetti veri.
    def _as_dict(f):
        if is_dataclass(f) and not isinstance(f, type):
            d = asdict(f)
            d.setdefault("engine", "yara")
            return d
        return f

    combined = [_as_dict(f) for engine_findings in results.values() for f in engine_findings]
    (paths.vuln_scanner_dir / "findings_all.json").write_text(
        json.dumps(combined, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )

    return results


def _phase_fuzzing(decompiled_c, paths: BinaryPaths):
    """
    Componente 2.4: genera un corpus di seed mirati in
    paths.fuzzing_dir/seeds/, usando lo pseudocodice decompilato, i
    finding del vuln_scanner (per le taglie) e il call graph prodotto
    dalla fase CFG (per la priorita' via raggiungibilita': quali
    funzioni di ingresso hanno davvero un cammino di chiamata verso
    codice gia' segnalato come vulnerabile).

    Non lancia una vera campagna AFL++: quella richiede WSL2/Linux
    (i binari sono ELF) e resta un passo manuale/da agganciare in
    futuro con il progetto di fuzzing esistente. Qui produciamo solo
    il corpus di input, coerente con l'output atteso dallo spec
    ("Corpus of fuzzing inputs").
    """
    if not decompiled_c:
        print("[!] Fuzzer seed generator saltato: nessuno pseudocodice decompilato disponibile")
        return

    seeds_dir = paths.fuzzing_dir / "seeds"
    findings_all = paths.vuln_scanner_dir / "findings_all.json"
    callgraph = paths.cfg_dir / "callgraph_named.graphml"
    if not callgraph.exists():
        # fallback: se il relabeling non e' avvenuto (es. symbols.json
        # mancante), il callgraph "grezzo" con nodi sub_XXXX esiste
        # comunque ma i nomi non combaciano con quelli dello
        # pseudocodice -> la raggiungibilita' verrebbe sempre vuota.
        # Meglio saltarla esplicitamente che fingere che funzioni.
        callgraph = None

    summary = generate_seed_corpus(
        decompiled_c,
        seeds_dir,
        findings_all if findings_all.exists() else None,
        callgraph,
    )

    print(f"[+] Fuzzer seed generator: {summary.input_functions_found} funzioni di ingresso, "
          f"{summary.seeds_written} seed scritti in {seeds_dir}")
    if summary.cfg_priority_functions:
        print(f"[!] Funzioni prioritarie (call graph -> codice vulnerabile noto): "
              f"{', '.join(summary.cfg_priority_functions)} -> copie in {seeds_dir / '_priority'}")
    if summary.input_functions_found == 0:
        print("[=] Nessuna funzione con input esterno individuata: normale se il binario "
              "non legge da file/stdin/rete/argv (es. usa solo dati hardcoded, come i test "
              "case char_type_overrun_memcpy attuali).")


def _phase_reporting(binary_name: str, paths: BinaryPaths, timing: dict | None, decompiled_c: Path | None = None):
    """
    Componente 2.5: aggrega finding (vuln_scanner), timing
    (decompilazione + CFG) e, se annotata, l'accuracy contro
    ground_truth.json nella root del progetto. Genera report.html
    (Jinja2) e report.sarif in paths.reporting_dir.

    decompiled_c: path allo pseudocodice completo decompilato da
    Ghidra per questo binario (lo stesso gia' prodotto dalla fase
    decompile e riusato da vuln_scanner/fuzz_seed_generator). Se
    presente, il report mostra il corpo intero della funzione per
    ogni finding invece di un semplice numero di riga (vedi
    reporting/code_context.py per il perche').

    Se sources/manifest.xml esiste (stesso file gia' usato per
    importare ground_truth.json), risolviamo anche i sorgenti Juliet
    originali con resolve_source_paths() e li passiamo al report per
    un confronto diretto decompilato/sorgente. Se il manifest non
    c'e', il report mostra comunque il solo decompilato: nessuna
    delle due fonti di codice e' un requisito, sono entrambe
    opzionali (vedi reporting/README.md).

    Il confronto "con seed guidati vs seed casuali" (punto 4.2 dello
    spec, Fuzzing Effectiveness) resta fuori per ora: richiede prima
    di eseguire davvero una campagna AFL++ (funzione a parte in
    pipe.py, volutamente non ancora integrata — vedi
    fuzz_seed_generator/README.md). generate_report() e' gia' pronta
    ad accoglierlo via il parametro fuzzing_effectiveness quando quei
    dati esisteranno.
    """
    findings_all = paths.vuln_scanner_dir / "findings_all.json"
    if not findings_all.exists():
        print("[!] Reporting saltato: nessun findings_all.json disponibile")
        return

    fuzzing_manifest = paths.fuzzing_dir / "seeds" / "manifest.json"

    source_paths = None
    if JULIET_MANIFEST_PATH.exists():
        source_paths = resolve_source_paths(binary_name, JULIET_MANIFEST_PATH, SOURCES_DIR)

    summary = generate_report(
        binary_name=binary_name,
        findings_all_json=findings_all,
        output_dir=paths.reporting_dir,
        timing=timing,
        project_root=Path.cwd(),
        fuzzing_manifest_json=fuzzing_manifest if fuzzing_manifest.exists() else None,
        fuzzing_seeds_dir=fuzzing_manifest.parent,
        decompiled_c_path=decompiled_c,
        source_c_paths=source_paths,
    )

    print(f"[+] Report generato: {paths.reporting_dir / 'report.html'} , "
          f"{paths.reporting_dir / 'report.sarif'}")
    if summary["accuracy_available"]:
        tpr = summary.get("true_positive_rate")
        tpr_str = f"{tpr:.0%}" if tpr is not None else "n/d"
        print(f"[*] Accuracy: true positive rate={tpr_str}, "
              f"falsi positivi={summary.get('false_positives', 0)}")
    else:
        print("[=] Nessuna ground truth annotata per questo binario in ground_truth.json "
              "(accuracy non calcolata, il report resta comunque generato)")


# ============================================================================
# ORCHESTRAZIONE
# ============================================================================

def run_pipeline_for_binary(binary_path: Path, risultati_dir: Path = RISULTATI_DIR) -> dict:
    """
    Esegue l'intera pipeline su UN binario. Ogni fase e' avvolta in un
    try/except: se una fase fallisce, la pipeline continua sulle fasi
    successive che non dipendono strettamente da essa (stesso spirito
    tollerante del vecchio main.py, che gia' gestiva l'assenza di
    symbols_json senza interrompersi).
    """
    binary_name = binary_path.name
    print("\n" + "=" * 70)
    print(f"[*] Pipeline: {binary_name}")
    print("=" * 70)

    paths = get_binary_paths(binary_name, risultati_dir)
    summary = {"binary": binary_name, "ok": True, "errors": []}

    try:
        _copy_binary(binary_path, paths)
    except Exception as e:
        summary["ok"] = False
        summary["errors"].append(f"copy: {e}")
        print(f"[!] Errore copia binario, pipeline interrotta per {binary_name}: {e}")
        traceback.print_exc()
        return summary

    try:
        target_path = _phase_unpack(paths)
    except Exception as e:
        summary["errors"].append(f"unpack: {e}")
        print(f"[!] Errore fase unpack, continuo con il binario originale: {e}")
        target_path = paths.bin_path

    decompiled_c, symbols_json = None, None
    decompile_seconds = None
    try:
        t0 = time.perf_counter()
        decompiled_c, symbols_json = _phase_decompile(target_path, paths)
        decompile_seconds = time.perf_counter() - t0
    except Exception as e:
        summary["errors"].append(f"decompile: {e}")
        print(f"[!] Errore fase decompile: {e}")
        traceback.print_exc()

    cfg_seconds = None
    try:
        t0 = time.perf_counter()
        _phase_cfg(target_path, symbols_json, paths)
        cfg_seconds = time.perf_counter() - t0
    except Exception as e:
        summary["errors"].append(f"cfg: {e}")
        print(f"[!] Errore fase CFG: {e}")
        traceback.print_exc()

    # timing.json: scritto su disco (non solo tenuto in memoria) cosi'
    # il Reporting Engine puo' anche essere rilanciato da solo in un
    # secondo momento, senza dover rieseguire tutta la pipeline.
    timing = None
    if decompile_seconds is not None or cfg_seconds is not None:
        timing = {
            "decompile_seconds": decompile_seconds,
            "cfg_seconds": cfg_seconds,
            "binary_size_bytes": target_path.stat().st_size if target_path.exists() else None,
        }
        (paths.root / "timing.json").write_text(json.dumps(timing, indent=2), encoding="utf-8")

    try:
        engine_results = _phase_vuln_scanner(decompiled_c, symbols_json, target_path, paths)
        summary["vuln_findings"] = {engine: len(f) for engine, f in engine_results.items()}
    except Exception as e:
        summary["errors"].append(f"vuln_scanner: {e}")
        print(f"[!] Errore fase vuln_scanner: {e}")
        traceback.print_exc()

    _phase_fuzzing(decompiled_c, paths)
    _phase_reporting(binary_name, paths, timing, decompiled_c)

    summary["ok"] = len(summary["errors"]) == 0
    return summary


def _import_ground_truth_if_available(
    manifest_path: Path = JULIET_MANIFEST_PATH,
    sources_dir: Path = SOURCES_DIR,
    output_path: Path = GROUND_TRUTH_PATH,
) -> None:
    """
    Se sources/manifest.xml esiste, importa/aggiorna ground_truth.json
    da li' PRIMA di processare i binari, cosi' la fase di reporting ha
    gia' la ground truth pronta senza un passo manuale separato.
    Usa la stessa funzione (build_ground_truth_from_manifest) che
    reporting/juliet_ground_truth_importer.py espone anche da CLI per
    un uso puntuale — stesso codice, due modi di invocarlo.

    Se il manifest non esiste, non fa nulla: e' una feature opzionale
    a costo zero, non un requisito della pipeline.
    """
    if not manifest_path.exists():
        return

    print(f"[*] Import ground truth da {manifest_path}...")
    try:
        imported = build_ground_truth_from_manifest(manifest_path, sources_dir)
        merged = merge_into_existing(imported, output_path)
        output_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
        total_expected = sum(len(v["expected"]) for v in merged.values())
        print(f"[+] Ground truth: {len(merged)} binari, {total_expected} debolezze attese -> {output_path}")
    except Exception as e:
        print(f"[!] Import ground truth fallito (la pipeline continua comunque): {e}")


def run_all(bins_dir: Path = BINS_DIR, risultati_dir: Path = RISULTATI_DIR) -> list[dict]:
    """Esegue run_pipeline_for_binary() su tutti i binari trovati in bins/."""
    _import_ground_truth_if_available()

    binaries = discover_binaries(bins_dir)
    if not binaries:
        print(f"[!] Nessun binario trovato in {bins_dir}")
        return []

    print(f"[*] {len(binaries)} binari trovati in {bins_dir}: "
          f"{', '.join(b.name for b in binaries)}")

    results = []
    for binary_path in binaries:
        results.append(run_pipeline_for_binary(binary_path, risultati_dir))

    print("\n" + "=" * 70)
    print("[*] RIEPILOGO PIPELINE")
    print("=" * 70)
    for r in results:
        status = "OK" if r["ok"] else "CON ERRORI"
        vuln = r.get("vuln_findings", {})
        findings_str = ", ".join(f"{engine}={n}" for engine, n in vuln.items()) or "-"
        print(f"  {r['binary']:<60} [{status}]  finding: {findings_str}")
        for err in r["errors"]:
            print(f"      - {err}")

    try:
        agg_summary = generate_aggregate_report(risultati_dir, Path.cwd(), risultati_dir / "aggregate_report.html")
        print(f"\n[+] Report aggregato: {risultati_dir / 'aggregate_report.html'}")
        if agg_summary["zero_finding_categories"]:
            print(f"[!] Categorie interamente a zero finding: {', '.join(agg_summary['zero_finding_categories'])}")
    except Exception as e:
        print(f"[!] Report aggregato non generato: {e}")

    return results


def run_only(binary_name: str, bins_dir: Path = BINS_DIR, risultati_dir: Path = RISULTATI_DIR) -> dict:
    _import_ground_truth_if_available()

    binary_path = bins_dir / binary_name
    if not binary_path.exists():
        raise FileNotFoundError(f"Binario non trovato in {bins_dir}: {binary_name}")
    return run_pipeline_for_binary(binary_path, risultati_dir)


# ============================================================================
# CLI
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Orchestratore pipeline di tesi")
    parser.add_argument("--only", metavar="NOME_BIN", help="Esegue solo su questo binario (nome file in bins/)")
    parser.add_argument("--list", action="store_true", help="Elenca i binari trovati in bins/ ed esce")
    parser.add_argument("--reset", metavar="NOME_BIN", help="Cancella risultati/<NOME_BIN>/ ed esce")
    parser.add_argument("--reset-all", action="store_true", help="Cancella tutta la cartella risultati/ ed esce")
    parser.add_argument("--redo", metavar="NOME_BIN", help="Reset + riesegue la pipeline su questo binario")
    args = parser.parse_args()

    if args.list:
        for b in discover_binaries():
            print(b.name)
        return

    if args.reset:
        reset_binary_results(args.reset)
        return

    if args.reset_all:
        reset_all_results()
        return

    if args.redo:
        reset_binary_results(args.redo)
        run_only(args.redo)
        return

    if args.only:
        run_only(args.only)
        return

    run_all()


if __name__ == "__main__":
    main()