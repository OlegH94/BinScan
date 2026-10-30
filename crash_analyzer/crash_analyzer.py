"""
crash_analyzer.py
--------------------------------------------------------------------
Per ogni crash trovato da AFL++ (campaign_with_seeds/ e
campaign_without_seeds/), esegue il binario sotto gdb in modalita'
batch con quel file come input, estrae segnale/indirizzo/nome
funzione dal backtrace, e recupera la funzione INTERA corrispondente
dal file decompiled.c gia' prodotto da Ghidra.

Scelta di design dichiarata: non mappa all'indirizzo alla RIGA esatta
di pseudocodice (richiederebbe estendere DecompScript.java per
esportare la corrispondenza indirizzo->riga che Ghidra tiene
internamente nel proprio AST del decompilatore — API interna non
verificabile senza un'istanza di Ghidra, quindi codice scritto "alla
cieca"). Si ferma invece al livello di FUNZIONE: gdb da' gia' gratis
il nome della funzione (i binari non sono stripped), e la funzione
intera (tipicamente 5-30 righe in questo dataset) si presta bene
all'ispezione a occhio una volta isolata.

Stesso pattern Docker gia' collaudato in fuzzing_runner.py e
cwe_checker_integration.py — qui usa la STESSA immagine
aflplusplus/aflplusplus (verificato: include gdb in /usr/bin/gdb),
nessuna dipendenza nuova.

NOTA SU COSA E' VERIFICATO E COSA NO: parsing dell'output di gdb ed
estrazione della funzione dal decompilato sono testati con dati
sintetici che replicano il formato osservato. L'esecuzione REALE di
gdb dentro il container contro un vero binario Juliet va verificata
nel tuo ambiente (nessun Docker/gdb disponibile qui).
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path

DOCKER_IMAGE = "aflplusplus/aflplusplus"

# Stessa firma di funzione usata altrove nel progetto (scanner.py,
# llm_reviewer/llm_review.py) — duplicata qui per tenere questo
# modulo autosufficiente, stessa scelta gia' fatta per gli altri.
_FUNC_SIGNATURE_RE = re.compile(r"^[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*\{", re.MULTILINE)

# File che AFL++ scrive nella cartella crashes/ oltre ai casi di test
# veri e propri — da ignorare durante la scansione.
_NON_CRASH_FILES = {"README.txt"}


class GdbNotAvailable(RuntimeError):
    """Docker non e' disponibile, o l'immagine aflplusplus non e' scaricata."""


def _check_docker_available() -> None:
    if shutil.which("docker") is None:
        raise GdbNotAvailable("docker non trovato nel PATH. Installa Docker Desktop e riprova.")


def _extract_function(decompiled_c_path: Path, function_name: str) -> str | None:
    """
    Estrae il testo completo di UNA funzione dal file decompiled.c,
    cercando la sua firma e prendendo tutto fino alla firma della
    funzione successiva (o alla fine del file).
    """
    if not decompiled_c_path.exists():
        return None

    source_text = decompiled_c_path.read_text(encoding="utf-8", errors="ignore")
    matches = list(_FUNC_SIGNATURE_RE.finditer(source_text))

    for i, m in enumerate(matches):
        if m.group(1) != function_name:
            continue
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source_text)
        return source_text[start:end].strip()

    return None


def _parse_gdb_backtrace(gdb_output: str) -> dict:
    """
    Estrae segnale, indirizzo e nome funzione dal backtrace. Formato
    tipico atteso (binari non stripped, nessuna informazione di debug
    a livello sorgente):

        Program received signal SIGSEGV, Segmentation fault.
        0x0000000000101277 in CWE121_..._fgets_01_bad ()
        #0  0x0000000000101277 in CWE121_..._fgets_01_bad ()
        #1  0x0000000000101350 in main ()

    Non ci fermiamo sempre al frame #0: una corruzione grave dello
    stack (osservato in produzione) puo' sovrascrivere l'indirizzo di
    ritorno con dati arbitrari, rendendo il simbolo AL FRAME #0 stesso
    non risolvibile (gdb stampa "??" al posto del nome). In quel caso
    scendiamo nei frame successivi finche' non ne troviamo uno con un
    simbolo risolto — spesso la funzione bersaglio ricompare qualche
    livello piu' sotto, anche quando il punto di crash immediato e'
    illeggibile.
    """
    signal_match = re.search(r"Program received signal (\w+)", gdb_output)
    signal = signal_match.group(1) if signal_match else None

    frame_pattern = re.compile(r"#(\d+)\s+(?:(0x[0-9a-fA-F]+)\s+in\s+)?(\S+)\s*\(")
    frames = frame_pattern.findall(gdb_output)

    address = None
    function_name = None
    crash_frame_index = None

    for frame_num, addr, name in frames:
        if name != "??":
            address = addr or None
            function_name = name
            crash_frame_index = int(frame_num)
            break

    return {
        "signal": signal,
        "address": address,
        "function_name": function_name,
        # 0 = crash diretto in una funzione risolta; >0 = il punto di
        # crash immediato non era risolvibile (probabile corruzione
        # grave), risolto scendendo di N livelli nel backtrace.
        "crash_frame_index": crash_frame_index,
    }


@dataclass
class CrashReport:
    crash_file: str
    campaign: str  # "with_seeds" | "without_seeds"
    signal: str | None
    address: str | None
    function_name: str | None
    crash_frame_index: int | None  # 0 = crash diretto; >0 = risolto scendendo nel backtrace (probabile corruzione)
    pseudocode: str | None
    gdb_output: str


def analyze_crash(
    binary_path: Path,
    crash_file: Path,
    decompiled_c_path: Path,
    campaign: str,
    docker_image: str = DOCKER_IMAGE,
    timeout_seconds: int = 30,
) -> CrashReport:
    _check_docker_available()

    binary_dir_abs = str(binary_path.parent.resolve())
    crash_dir_abs = str(crash_file.parent.resolve())

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{binary_dir_abs}:/target_bin:ro",
        "-v", f"{crash_dir_abs}:/crash_dir:ro",
        docker_image,
        "gdb", "-batch",
        "-ex", f"run < /crash_dir/{crash_file.name}",
        "-ex", "bt",
        "-ex", "quit",
        f"/target_bin/{binary_path.name}",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        gdb_output = result.stdout + "\n" + result.stderr
    except subprocess.TimeoutExpired:
        gdb_output = f"[timeout dopo {timeout_seconds}s: il binario potrebbe essere entrato in un loop invece di crashare]"

    parsed = _parse_gdb_backtrace(gdb_output)
    pseudocode = _extract_function(decompiled_c_path, parsed["function_name"]) if parsed["function_name"] else None

    return CrashReport(
        crash_file=crash_file.name,
        campaign=campaign,
        signal=parsed["signal"],
        address=parsed["address"],
        function_name=parsed["function_name"],
        crash_frame_index=parsed["crash_frame_index"],
        pseudocode=pseudocode,
        gdb_output=gdb_output,
    )


def find_crash_files(campaign_output_dir: Path) -> list[Path]:
    """
    AFL++ scrive i crash in <out>/default/crashes/ (versioni recenti)
    o <out>/crashes/ (piu' vecchie) — controlliamo entrambi, stesso
    principio gia' usato per fuzzer_stats in fuzzing_runner.py.
    """
    candidates = [campaign_output_dir / "default" / "crashes", campaign_output_dir / "crashes"]
    crashes_dir = next((p for p in candidates if p.exists()), None)
    if crashes_dir is None:
        return []

    return sorted(f for f in crashes_dir.iterdir() if f.is_file() and f.name not in _NON_CRASH_FILES)


def analyze_all_crashes(
    binary_root: Path,
    binary_name: str,
    docker_image: str = DOCKER_IMAGE,
) -> list[CrashReport]:
    """
    Scansiona sia campaign_with_seeds/ sia campaign_without_seeds/ per
    QUESTO binario, analizza ogni crash trovato in entrambe.
    """
    binary_path = binary_root / "bin" / binary_name
    decompiled_c_path = binary_root / "decompiled_files" / f"{binary_name}_decompiled.c"

    reports: list[CrashReport] = []

    for campaign, subdir in [("with_seeds", "campaign_with_seeds"), ("without_seeds", "campaign_without_seeds")]:
        campaign_dir = binary_root / "fuzzing" / subdir
        crash_files = find_crash_files(campaign_dir)

        for crash_file in crash_files:
            print(f"    [*] Analisi di {crash_file.name} ({campaign})...")
            report = analyze_crash(binary_path, crash_file, decompiled_c_path, campaign, docker_image)
            reports.append(report)

    return reports