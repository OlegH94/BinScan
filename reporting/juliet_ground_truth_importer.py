"""
juliet_ground_truth_importer.py
--------------------------------------------------------------------
Converte il manifest XML di Juliet (quello con <testcase><file
path="..."><flaw line="N" name="CWE-XXX: ..."/></file></...>) nel
ground_truth.json che accuracy.py si aspetta — invece di scriverlo a
mano binario per binario.

Due cose che il manifest NON dice direttamente e che dobbiamo dedurre:

1. Il NOME DEL BINARIO compilato. Juliet elenca i singoli file
   sorgente (es. "..._51a.c" + "..._51b.c" per un testcase a due
   file), ma voi compilate unendoli in un unico binario. Dalla
   convenzione osservata nei vostri binari gia' pronti:
     - un solo file "..._01.c"        -> binario "..._01-bad"
     - due file "..._51a.c"+"..._51b.c" -> binario "..._51-bad"
   cioe': si toglie la lettera finale di variante (a, b, c...) quando
   ce n'e' piu' di una, si tiene il nome intero se il testcase e' a
   file singolo, e si aggiunge sempre il suffisso "-bad" (per ora
   importiamo solo i binari "bad": sono quelli con la debolezza,
   coerente con come avete popolato bins/ finora).

2. La FUNZIONE che contiene la riga del flaw. Il manifest da' solo un
   numero di riga nel sorgente originale — cerchiamo quale funzione
   la contiene scandendo le firme di funzione nel file .c (stesso
   principio dello splitter di funzioni usato nel vuln_scanner e nel
   fuzz_seed_generator, qui applicato a sorgente C vero invece che a
   pseudocodice Ghidra).

Uso:
    python juliet_ground_truth_importer.py \
        --manifest sources/manifest_CWE121_subset.xml \
        --sources-dir sources/ \
        --output ground_truth.json
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# Default pensati per lanciare lo script direttamente da PyCharm (Run,
# senza configurare argomenti a riga di comando) invece che da CLI.
# Il comportamento di default e' la modalita' "filtra il manifest
# completo sulla selezione" (quella che serve ora); per l'altra
# modalita' (costruire ground_truth.json direttamente) passate
# esplicitamente --filter "" e --sources-dir da riga di comando o da
# una Run Configuration di PyCharm con parametri.
#
# I path relativi sono calcolati rispetto alla ROOT DEL PROGETTO
# (dedotta dalla posizione di questo file: reporting/../ ), non
# rispetto alla working directory corrente — PyCharm spesso imposta
# la working directory sulla cartella dello script stesso (reporting/)
# quando lo lanci con Run da li', non sulla root del progetto, e un
# path relativo tipo "selected_bins.txt" verrebbe cercato nel posto
# sbagliato (bug osservato: FileNotFoundError anche col file presente
# nella root del progetto).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_MANIFEST_PATH = r"<JULIET_DIR>\manifest.xml"
DEFAULT_SELECTION_FILE = str(_PROJECT_ROOT / "selected_bins.txt")
DEFAULT_FILTERED_OUTPUT = str(_PROJECT_ROOT / "sources" / "manifest.xml")

# Firma di funzione in sorgente C "vero" (non pseudocodice Ghidra):
# a differenza delle regex usate altrove nel progetto, qui la graffa
# puo' stare sulla stessa riga della firma o su quella dopo — lo stile
# dei template Juliet e' quasi sempre "a capo", ma restiamo permissivi.
_FUNC_SIGNATURE_RE = re.compile(
    r"^[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*\{", re.MULTILINE
)

# La regex sopra e' sintatticamente indistinguibile da uno statement di
# controllo ("if (...) {", "for (...) {", ecc.): entrambi sono "parola
# (...) {". Bug reale scoperto in produzione: un flaw dentro un blocco
# if veniva attribuito alla "funzione" if invece che alla vera funzione
# che lo contiene — il caso piu' comune in assoluto (i flaw Juliet sono
# quasi sempre dentro un if), quindi questo filtro e' essenziale, non
# un dettaglio marginale.
_C_CONTROL_KEYWORDS = {"if", "else", "for", "while", "switch", "do", "return", "sizeof"}

_TRAILING_LETTER_RE = re.compile(r"^(.*)([a-z])$")


def _binary_name_for_testcase(file_paths: list[str], suffix: str = "-bad") -> str:
    """
    Deriva il nome del binario compilato dai file sorgente di un
    singolo <testcase>. Solleva ValueError se i file non condividono
    lo stesso nome base una volta tolta la lettera finale di variante
    (segno che l'assunzione di naming non vale per questo testcase:
    meglio fermarsi che generare una entry sbagliata in silenzio).
    """
    stems = [Path(p).stem for p in file_paths]

    if len(stems) == 1:
        return f"{stems[0]}{suffix}"

    bases = set()
    for s in stems:
        m = _TRAILING_LETTER_RE.match(s)
        bases.add(m.group(1) if m else s)

    if len(bases) != 1:
        raise ValueError(f"Nomi file incoerenti nello stesso testcase, impossibile dedurre il binario: {file_paths}")

    return f"{bases.pop()}{suffix}"


def filter_manifest_by_selection(
    manifest_path: str | Path,
    selection_file: str | Path,
    output_path: str | Path,
    binary_suffix: str = "-bad",
) -> int:
    """
    Legge il manifest COMPLETO di Juliet (es. migliaia di <testcase>)
    e ne scrive uno piu' piccolo contenente solo i <testcase> il cui
    binario derivato (stessa logica di _binary_name_for_testcase) e'
    elencato in selection_file (un nome binario per riga, come
    selected_bins.txt). Il file risultante e' pronto per essere messo
    in sources/manifest.xml e usato sia da build_ground_truth_from_manifest()
    sia dall'import automatico gia' collegato in pipe.py.

    Ritorna il numero di testcase mantenuti (utile per un log rapido:
    se e' molto minore del numero di righe in selection_file, alcuni
    binari selezionati non sono stati trovati nel manifest completo).
    """
    selected = {
        line.strip() for line in Path(selection_file).read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    tree = ET.parse(str(manifest_path))
    root = tree.getroot()

    new_root = ET.Element(root.tag, root.attrib)
    kept = 0

    for testcase in root.findall("testcase"):
        file_paths = [f.get("path") for f in testcase.findall("file")]
        try:
            binary_name = _binary_name_for_testcase(file_paths, binary_suffix)
        except ValueError:
            continue  # stessa logica di build_ground_truth_from_manifest: meglio saltare che sbagliare

        if binary_name in selected:
            new_root.append(testcase)
            kept += 1

    new_tree = ET.ElementTree(new_root)
    try:
        ET.indent(new_tree, space="  ")  # Python 3.9+, solo per leggibilita' del file scritto
    except AttributeError:
        pass

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    new_tree.write(str(output_path), encoding="utf-8", xml_declaration=True)

    missing = len(selected) - kept
    print(f"[+] {kept} testcase trovati e scritti in {output_path}")
    if missing > 0:
        print(f"[!] {missing} binari della selezione non trovati nel manifest completo "
              f"(nome derivato non corrisponde a nessun testcase — verificare la convenzione di naming)")

    return kept


def _find_enclosing_function(source_text: str, line_number: int) -> str | None:
    """
    Trova il nome della funzione che contiene `line_number` (1-based),
    cercando l'ultima firma di funzione che inizia PRIMA di quella riga.
    Ritorna None se non trova nessuna funzione precedente (riga fuori
    da qualunque corpo di funzione, es. una define globale).
    """
    matches = list(_FUNC_SIGNATURE_RE.finditer(source_text))
    if not matches:
        return None

    best_name = None
    for m in matches:
        name = m.group(1)
        if name in _C_CONTROL_KEYWORDS:
            continue  # e' un if/for/while/..., non una funzione: ignora e continua

        start_line = source_text.count("\n", 0, m.start()) + 1
        if start_line <= line_number:
            best_name = name
        else:
            break

    return best_name


def build_ground_truth_from_manifest(
    manifest_xml_path: str | Path,
    sources_dir: str | Path,
    binary_suffix: str = "-bad",
) -> dict:
    """
    Ritorna il dict ground_truth pronto per essere scritto come JSON
    (stessa forma attesa da reporting/accuracy.py).
    """
    sources_dir = Path(sources_dir)
    tree = ET.parse(str(manifest_xml_path))
    root = tree.getroot()

    ground_truth: dict[str, dict] = {}
    skipped: list[str] = []

    for testcase in root.findall("testcase"):
        file_elements = testcase.findall("file")
        file_paths = [f.get("path") for f in file_elements]

        try:
            binary_name = _binary_name_for_testcase(file_paths, binary_suffix)
        except ValueError as e:
            skipped.append(str(e))
            continue

        expected: list[dict] = []
        for file_el in file_elements:
            flaws = file_el.findall("flaw")
            if not flaws:
                continue  # file "di supporto" nel testcase, senza debolezza propria (es. il file "...a.c" nell'esempio a due file)

            source_path = sources_dir / file_el.get("path")
            if not source_path.exists():
                skipped.append(f"sorgente mancante: {source_path}")
                continue

            source_text = source_path.read_text(encoding="utf-8", errors="ignore")

            for flaw in flaws:
                line = int(flaw.get("line"))
                cwe_full = flaw.get("name", "")  # es. "CWE-121: Stack-based Buffer Overflow"
                cwe = cwe_full.split(":")[0].strip()

                func_name = _find_enclosing_function(source_text, line)
                if func_name is None:
                    skipped.append(f"nessuna funzione trovata per {source_path}:{line}")
                    continue

                expected.append({"cwe": cwe, "function": func_name})

        if expected:
            ground_truth.setdefault(binary_name, {"expected": []})["expected"].extend(expected)

    if skipped:
        print(f"[!] {len(skipped)} voci saltate durante l'importazione:")
        for s in skipped[:20]:
            print(f"    - {s}")
        if len(skipped) > 20:
            print(f"    ... e altre {len(skipped) - 20}")

    return ground_truth


def merge_into_existing(new_ground_truth: dict, existing_path: str | Path) -> dict:
    """
    Se ground_truth.json esiste gia' (es. avete gia' annotato altri
    binari a mano), unisce invece di sovrascrivere. In caso di stesso
    nome binario in entrambi, vince il nuovo import (assumiamo che
    l'import da Juliet sia piu' affidabile di eventuali voci scritte
    a mano in precedenza per lo stesso binario).
    """
    existing_path = Path(existing_path)
    if not existing_path.exists():
        return new_ground_truth

    try:
        existing = json.loads(existing_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"[!] {existing_path} esistente non e' JSON valido, verra' sovrascritto")
        return new_ground_truth

    existing.update(new_ground_truth)
    return existing


def resolve_source_paths(
    binary_name: str,
    manifest_xml_path: str | Path,
    sources_dir: str | Path,
    binary_suffix: str = "-bad",
) -> list[Path]:
    """
    Dato il nome di un binario gia' compilato (es. per il report),
    ritorna i path assoluti ai file sorgente originali che lo
    compongono, cercando nel manifest il <testcase> il cui binario
    derivato (stessa convenzione di _binary_name_for_testcase) coincide
    con `binary_name`.

    Pensato per essere chiamato da pipe.py subito prima di
    reporting.report_generator.generate_report(), per popolare
    `source_c_paths` senza dover indovinare a mano la convenzione di
    naming (gia' delicata, vedi i commenti su _binary_name_for_testcase
    e sul bug storico del blocco if scambiato per funzione).

    Ritorna una lista vuota (non solleva eccezioni) se il binario non
    viene trovato nel manifest, o se un file sorgente elencato non
    esiste su disco - lo stesso principio "degrada con grazia" del
    resto del Reporting Engine: il report deve restare generabile
    anche senza il sorgente originale, mostrando solo il decompilato.
    """
    sources_dir = Path(sources_dir)
    tree = ET.parse(str(manifest_xml_path))
    root = tree.getroot()

    for testcase in root.findall("testcase"):
        file_paths = [f.get("path") for f in testcase.findall("file")]
        try:
            derived_name = _binary_name_for_testcase(file_paths, binary_suffix)
        except ValueError:
            continue

        if derived_name != binary_name:
            continue

        resolved = []
        for p in file_paths:
            full_path = sources_dir / p
            if full_path.exists():
                resolved.append(full_path)
            else:
                print(f"[!] Sorgente elencato nel manifest ma non trovato su disco, ignorato: {full_path}")
        return resolved

    print(f"[!] Nessun testcase nel manifest produce il binario '{binary_name}', "
          f"nessun sorgente risolto (il report mostrera' solo il decompilato).")
    return []


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Importa ground_truth.json dal manifest XML di Juliet, o filtra il manifest completo su una selezione")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST_PATH, help="Path al manifest XML (completo o gia' un sottoinsieme di <testcase>)")
    parser.add_argument("--sources-dir", default=None, help="Cartella con i sorgenti .c originali (richiesto se non si usa --filter)")
    parser.add_argument("--output", default="ground_truth.json", help="Path del ground_truth.json da scrivere (ignorato con --filter)")
    parser.add_argument("--suffix", default="-bad", help="Suffisso del nome binario (default: -bad)")
    parser.add_argument("--merge", action="store_true", help="Unisce con un ground_truth.json esistente invece di sovrascriverlo (ignorato con --filter)")
    parser.add_argument("--filter", metavar="SELECTION_FILE", default=DEFAULT_SELECTION_FILE,
                         help="Invece di costruire ground_truth.json, filtra --manifest sui binari elencati in questo file "
                              "(un nome per riga, es. selected_bins.txt) e scrive il manifest ridotto in --filtered-output. "
                              "Attivo di default (vedi DEFAULT_SELECTION_FILE in cima al file): passate --filter \"\" "
                              "per disattivarlo e usare invece la modalita' costruzione diretta di ground_truth.json.")
    parser.add_argument("--filtered-output", default=DEFAULT_FILTERED_OUTPUT,
                         help="Path del manifest filtrato da scrivere quando si usa --filter (default: sources/manifest.xml, "
                              "lo stesso path che pipe.py cerca in automatico)")
    args = parser.parse_args()

    if args.filter:
        filter_manifest_by_selection(args.manifest, args.filter, args.filtered_output, args.suffix)
    else:
        if not args.sources_dir:
            parser.error("--sources-dir e' richiesto quando non si usa --filter")

        result = build_ground_truth_from_manifest(args.manifest, args.sources_dir, args.suffix)

        if args.merge:
            result = merge_into_existing(result, args.output)

        Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        total_expected = sum(len(v["expected"]) for v in result.values())
        print(f"[+] {len(result)} binari, {total_expected} debolezze attese -> {args.output}")