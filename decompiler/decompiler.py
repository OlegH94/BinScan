import subprocess
import os
from pathlib import Path

GHIDRA_HEADLESS = os.environ.get(
    "GHIDRA_HEADLESS",
    r"<GHIDRA_INSTALL_DIR>\support\analyzeHeadless.bat",  # set the GHIDRA_HEADLESS env var
)
PROJECT_DIR = r"binaries"
PROJECT_NAME = "Project"
POST_SCRIPT = r"DecompScript.java"

# Stessa cartella hardcoded dentro DecompScript.java ("decompiled_files/").
# Tenuta qui come costante cosi' le due parti (Java + Python) restano
# sincronizzate in un punto solo se in futuro la cambiate.
DECOMPILED_DIR = "decompiled_files"


def decompile(binary: Path, output_dir: Path):
    """
    Lancia Ghidra headless su `binary` con DecompScript.java.

    `output_dir` e' la cartella di risultati dedicata a QUESTO binario
    (dentro risultati/<nome_bin>/ nella pipeline). Il progetto Ghidra
    (PROJECT_DIR) e la cartella "decompiled_files/" scritta da
    DecompScript.java sono entrambi path RELATIVI: lanciamo il
    sottoprocesso con cwd=output_dir cosi' finiscono entrambi dentro
    output_dir senza dover toccare DecompScript.java (che resta
    condiviso e identico per ogni binario).

    Ritorna una tupla (decompiled_c_path, symbols_json_path):
    entrambi Path se il rispettivo file esiste dopo l'esecuzione,
    altrimenti None per quello mancante (es. se Ghidra e' fallito
    prima di scrivere l'output, o se usate una versione di
    DecompScript.java precedente all'aggiunta dell'export simboli).
    """
    print("-> decompilation start")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Ghidra NON crea da se' la cartella del progetto: si aspetta che
    # esista gia' prima di -import, altrimenti fallisce con
    # "Directory not found: .../binaries". output_dir.mkdir() sopra
    # crea solo la cartella risultati/<nome_bin>/, non la sottocartella
    # PROJECT_DIR al suo interno.
    (output_dir / PROJECT_DIR).mkdir(parents=True, exist_ok=True)

    # Stesso identico problema per DECOMPILED_DIR: DecompScript.java
    # scrive con new FileWriter("decompiled_files/...") relativo alla
    # cwd, e in Java FileWriter/FileOutputStream NON creano le
    # directory mancanti nel percorso (a differenza di Python) -
    # falliscono con FileNotFoundException se "decompiled_files/" non
    # esiste gia'. Prima funzionava perche' quella cartella restava
    # dalla vecchia struttura a binario singolo (creata una volta e
    # riusata); ora che ogni binario ha una risultati/<nome_bin>/
    # sempre nuova, va creata esplicitamente qui.
    (output_dir / DECOMPILED_DIR).mkdir(parents=True, exist_ok=True)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # binary va reso assoluto: dopo che il sottoprocesso parte con
    # cwd=output_dir, un path relativo verrebbe risolto rispetto a
    # output_dir invece che alla directory da cui gira pipe.py.
    binary_abs = str(Path(binary).resolve())

    cmd = [
        GHIDRA_HEADLESS,
        PROJECT_DIR,
        PROJECT_NAME,
        "-import", binary_abs,
        "-scriptPath", script_dir,
        "-postScript", POST_SCRIPT,
        "-overwrite"
    ]

    # Popen + lettura riga per riga invece di subprocess.run(capture_output=True):
    # con capture_output=True l'intero stdout/stderr di Ghidra resta
    # bufferizzato e invisibile finche' il processo non termina, quindi
    # per un binario che richiede alcuni minuti sembra "bloccato" anche
    # quando sta lavorando normalmente. Cosi' invece ogni riga di log
    # di Ghidra viene stampata appena disponibile.
    print(f"    (comando: {' '.join(cmd)})")
    process = subprocess.Popen(
        cmd,
        cwd=str(output_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # unifica stderr nello stesso stream di stdout
        text=True,
        bufsize=1,  # line-buffered
    )

    for line in process.stdout:
        print("    [ghidra] " + line.rstrip())

    process.wait()

    if process.returncode != 0:
        print(f"[!] Ghidra e' terminato con codice di uscita {process.returncode}")

    # currentProgram.getName() in Ghidra corrisponde al nome file
    # importato (con estensione), quindi usiamo binary.name per
    # ricostruire lo stesso path scritto da DecompScript.java.
    binary_name = Path(binary).name
    decompiled_c = output_dir / DECOMPILED_DIR / f"{binary_name}_decompiled.c"
    symbols_json = output_dir / DECOMPILED_DIR / f"{binary_name}_symbols.json"

    if not decompiled_c.exists():
        print(f"[!] Attenzione: {decompiled_c} non trovato (Ghidra e' fallito?)")
        decompiled_c = None

    if not symbols_json.exists():
        print(f"[!] Attenzione: {symbols_json} non trovato "
              f"(serve la versione aggiornata di DecompScript.java)")
        symbols_json = None

    return decompiled_c, symbols_json