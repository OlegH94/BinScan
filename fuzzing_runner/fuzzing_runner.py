"""
fuzzing_runner.py
--------------------------------------------------------------------
Esecuzione vera del fuzzing (componente lasciato volutamente "a parte"
per tutta la durata del progetto): due campagne AFL++ per binario
fuzzabile, una con i seed gia' generati da fuzz_seed_generator, una
con un seed banale generico — per confrontare l'efficacia.

Riusa lo stesso pattern gia' collaudato in cwe_checker_integration.py
(docker run --rm -v ...), qui puntato all'immagine ufficiale
aflplusplus/aflplusplus (QEMU mode incluso, verificato presente in
/usr/local/bin/afl-qemu-trace) invece che a quella di cwe_checker.

Perche' Docker e non un'installazione nativa AFL++ in WSL2: evita di
dover compilare a mano il supporto QEMU (build storicamente fragile,
dipendenze glib/pixman, patch), e mantiene tutta l'orchestrazione
dentro lo stesso ambiente Windows/Python del resto della pipeline.

Limite di scope dichiarato (v1): fuzza solo le funzioni di ingresso
classificate come "stdin_scanf" o "file" da fuzz_seed_generator.
Esclude esplicitamente "network" (richiederebbe un wrapper aggiuntivo
tipo desock/preeny per reindirizzare recv() a stdin — non incluso qui)
e "argv" (il modello standard "-i seed -o out -- bin @@" di AFL fuzza
il CONTENUTO di un file passato come argomento, non il valore letterale
di un argomento da riga di comando — i due casi non sono equivalenti
e un binario che legge da argv[] direttamente non e' fuzzabile in modo
significativo con questo approccio senza un harness dedicato).

NOTA IMPORTANTE SU COSA E' STATO VERIFICATO E COSA NO: questo modulo e'
stato scritto e testato SOLO nella sua logica Python pura (parsing di
fuzzer_stats, selezione dei binari fuzzabili, costruzione del comando
docker) — l'ambiente di sviluppo non ha accesso a Docker, quindi
l'esecuzione REALE di una campagna AFL++ dentro il container va
verificata nel tuo ambiente. Se il comando docker costruito qui non
funziona esattamente come scritto (nomi delle env var, formato esatto
di fuzzer_stats per la tua versione di AFL++), correggilo li' — la
struttura generale (due campagne, parsing chiave:valore, confronto)
resta valida.

AGGIORNAMENTO 27/09: verificato empiricamente (su
CWE121_..._fgets_01-bad, seed standard + seed mirati) che la modalita'
QEMU ("-Q") causa una sistematica misclassificazione crash->hang sui
fault che richiedono un accesso a un indirizzo molto lontano dallo
stack (es. un indice intero enorme usato come offset di array):
l'overhead di traduzione dinamica di QEMU sembra ritardare la
manifestazione del SIGSEGV oltre il timeout per-esecuzione di AFL,
che quindi termina il processo per timeout e lo conta come hang
invece che come crash — anche alzando il timeout a 5000ms+. Con "-n"
(dumb mode, nessuna istrumentazione, esecuzione nativa, niente QEMU),
lo stesso identico corpus di seed sullo stesso binario ha prodotto
crash correttamente rilevati in pochi secondi. Per questo run_campaign
ora accetta un parametro qemu (default False = usa "-n"): il dataset
"-Q" gia' raccolto resta valido per il confronto sull'ESPLORAZIONE
(percorsi unici con/senza seed), il dataset "-n" e' quello da usare
per contare i crash in modo affidabile. Vedi la tesi, sezione 6.6, per
la discussione completa di questo limite metodologico.

Uso:
    from fuzzing_runner import discover_fuzzable_binaries, run_campaign, parse_fuzzer_stats

    for target in discover_fuzzable_binaries(Path("risultati")):
        result_with = run_campaign(target, with_seeds=True, duration_seconds=120)
        result_without = run_campaign(target, with_seeds=False, duration_seconds=120)
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

DOCKER_IMAGE = "aflplusplus/aflplusplus"

# Tipi di ingresso di fuzz_seed_generator che sappiamo fuzzare con il
# modello standard "file passato come argomento" o "stdin" di AFL++.
_SUPPORTED_KINDS = {"stdin_scanf", "file"}

# Env var comunemente necessarie per far girare AFL++ dentro un
# container Docker senza che si blocchi sui controlli di sistema che
# in un container non sono configurabili (core_pattern, cpu scaling).
# Verificate empiricamente in molte guide/issue AFL++, ma non testate
# qui direttamente (nessun Docker in questo ambiente di sviluppo) —
# se la campagna si rifiuta di partire con un errore su questi
# argomenti specifici, e' il primo posto dove guardare.
_DOCKER_AFL_ENV = {
    "AFL_NO_UI": "1",
    "AFL_SKIP_CPUFREQ": "1",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
    "AFL_IGNORE_SEED_PROBLEMS": "1",
}


class FuzzingNotAvailable(RuntimeError):
    """Docker non e' disponibile, o l'immagine aflplusplus non e' scaricata."""


def _check_docker_available() -> None:
    if shutil.which("docker") is None:
        raise FuzzingNotAvailable("docker non trovato nel PATH. Installa Docker Desktop e riprova.")


@dataclass
class FuzzableTarget:
    binary_name: str
    binary_path: Path       # risultati/<nome_bin>/bin/<nome_bin>
    seeds_dir: Path          # risultati/<nome_bin>/fuzzing/seeds
    kind: str                # "stdin_scanf" o "file"
    output_root: Path        # risultati/<nome_bin>/fuzzing


def discover_fuzzable_binaries(risultati_dir: str | Path) -> list[FuzzableTarget]:
    """
    Scansiona risultati/*/fuzzing/seeds/manifest.json e ritorna solo i
    binari con almeno una funzione di ingresso di tipo supportato
    (stdin_scanf o file) — esclude silenziosamente "network"/"argv"
    (loggando il motivo) e i binari senza alcuna funzione di ingresso
    (dati hardcoded, gia' segnalati come "0 funzioni di ingresso" dal
    fuzz_seed_generator).
    """
    risultati_dir = Path(risultati_dir)
    targets: list[FuzzableTarget] = []

    for binary_dir in sorted(risultati_dir.iterdir()):
        if not binary_dir.is_dir():
            continue

        manifest_path = binary_dir / "fuzzing" / "seeds" / "manifest.json"
        if not manifest_path.exists():
            continue

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue

        if not manifest:
            continue

        # Juliet: praticamente sempre un solo comportamento per binario,
        # quindi il "kind" della prima entry rappresenta il programma
        # nel suo insieme (main() chiama sempre una sola vera funzione
        # di ingresso). Se in futuro un binario avesse piu' kind diversi
        # mescolati, prendiamo comunque solo il primo — caso non
        # osservato nel dataset Juliet CWE-121.
        kind = manifest[0].get("kind")

        binary_name = binary_dir.name
        binary_path = binary_dir / "bin" / binary_name

        if kind not in _SUPPORTED_KINDS:
            print(f"[=] {binary_name}: tipo di ingresso '{kind}' non supportato in questa versione, salto "
                  f"({'serve un wrapper desock/preeny' if kind == 'network' else 'serve un harness dedicato per argv'})")
            continue

        if not binary_path.exists():
            print(f"[!] {binary_name}: binario non trovato in {binary_path}, salto")
            continue

        targets.append(FuzzableTarget(
            binary_name=binary_name,
            binary_path=binary_path,
            seeds_dir=binary_dir / "fuzzing" / "seeds",
            kind=kind,
            output_root=binary_dir / "fuzzing",
        ))

    return targets


def _prepare_trivial_seed_dir(tmp_dir: Path) -> Path:
    """
    "Senza seed" in AFL++ non significa zero file: il fuzzer richiede
    sempre almeno un test case di partenza. Un singolo file banale
    (un byte) e' l'equivalente pratico di "nessun seed guidato" —
    il confronto e' quindi "seed mirati" vs "seed generico minimo",
    non "con input" vs "senza input" in senso assoluto.
    """
    trivial_dir = tmp_dir / "trivial_seed"
    trivial_dir.mkdir(parents=True, exist_ok=True)
    (trivial_dir / "seed").write_bytes(b"A")
    return trivial_dir


def _collect_real_seeds(seeds_dir: Path, tmp_dir: Path) -> Path:
    """
    fuzz_seed_generator scrive i seed in sottocartelle per funzione
    (seeds/<nome_funzione>/<file>) — AFL++ vuole tutti i file di
    partenza in UNA sola cartella piatta, quindi li raccogliamo qui.
    Esclude la sottocartella _priority/ (sono copie di seed gia'
    presenti altrove, evitiamo di duplicarli nel corpus di partenza).
    """
    flat_dir = tmp_dir / "real_seeds"
    flat_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for seed_file in seeds_dir.rglob("*"):
        if not seed_file.is_file():
            continue
        if seed_file.name == "manifest.json":
            continue
        if "_priority" in seed_file.parts:
            continue
        dest = flat_dir / f"{count:04d}_{seed_file.name}"
        shutil.copy2(seed_file, dest)
        count += 1

    if count == 0:
        raise FuzzingNotAvailable(f"Nessun file di seed reale trovato in {seeds_dir} (solo manifest.json?)")

    return flat_dir


def run_campaign(
    target: FuzzableTarget,
    with_seeds: bool,
    duration_seconds: int = 120,
    docker_image: str = DOCKER_IMAGE,
    qemu: bool = False,
    extra_args: list[str] | None = None,
) -> dict:
    """
    Esegue UNA campagna AFL++ (con o senza i seed generati) per
    duration_seconds, poi ritorna le statistiche parsate da
    fuzzer_stats. La cartella di output persiste su disco in
    target.output_root / ("campaign_with_seeds" | "campaign_without_seeds")
    per ispezione manuale (inclusi eventuali crash trovati).

    qemu=False (default, dal 27/09): usa "-n" (dumb mode, nessuna
    istrumentazione, esecuzione nativa) invece di "-Q" (QEMU mode).
    Verificato empiricamente che "-Q" causa una sistematica
    misclassificazione crash->hang su fault che richiedono accesso a
    indirizzi molto lontani dallo stack (overhead di traduzione QEMU
    che supera il timeout per-esecuzione prima che SIGSEGV si
    manifesti) — vedi test comparativo del 27/09 su fgets_01-bad:
    0 crash/2 hang con -Q anche con -t 5000+, contro 3 crash/0 hang
    con -n a parita' di seed e budget di tempo. qemu=True resta
    disponibile per rilanciare la vecchia modalita' se necessario
    (es. per il confronto sull'esplorazione/coverage, dove "-n" non
    fornisce feedback e riporta sempre 0% coverage).
    """
    _check_docker_available()

    campaign_name = "campaign_with_seeds" if with_seeds else "campaign_without_seeds"
    output_dir = target.output_root / campaign_name
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        input_dir = _collect_real_seeds(target.seeds_dir, tmp_path) if with_seeds else _prepare_trivial_seed_dir(tmp_path)

        binary_dir_abs = str(target.binary_path.parent.resolve())
        input_dir_abs = str(input_dir.resolve())
        output_dir_abs = str(output_dir.resolve())

        target_in_container = f"/target_bin/{target.binary_path.name}"
        afl_args = ["afl-fuzz", "-Q" if qemu else "-n", "-i", "/in", "-o", "/out", "-V", str(duration_seconds)]
        if target.kind == "file":
            afl_args += ["--", target_in_container, *(extra_args or []), "@@"]
        else:
            afl_args += ["--", target_in_container]

        cmd = ["docker", "run", "--rm"]
        for k, v in _DOCKER_AFL_ENV.items():
            cmd += ["-e", f"{k}={v}"]
        cmd += [
            "-v", f"{binary_dir_abs}:/target_bin:ro",
            "-v", f"{input_dir_abs}:/in:ro",
            "-v", f"{output_dir_abs}:/out",
            docker_image,
        ] + afl_args

        # Timeout del sottoprocesso con margine di sicurezza oltre la
        # durata richiesta ad AFL (-V): l'avvio del container + il
        # caricamento di QEMU per il primo run di calibrazione
        # richiedono qualche decina di secondi in piu' della durata
        # di fuzzing pura.
        subprocess_timeout = duration_seconds + 120

        print(f"[*] {target.binary_name}: campagna {'CON' if with_seeds else 'SENZA'} seed, "
              f"{duration_seconds}s ({'QEMU' if qemu else 'dumb, no QEMU'})...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=subprocess_timeout)

        if result.returncode != 0:
            print(f"[!] {target.binary_name}: docker terminato con codice {result.returncode}")
            print(f"    stderr: {result.stderr[:500]}")

    stats = parse_fuzzer_stats(output_dir)
    stats["binary"] = target.binary_name
    stats["with_seeds"] = with_seeds
    return stats


def parse_fuzzer_stats(output_dir: Path) -> dict:
    """
    fuzzer_stats e' un file testuale chiave : valore scritto da
    AFL++. Il path esatto varia leggermente tra versioni/modalita':
    <out>/default/fuzzer_stats per una singola istanza (-M/-S non
    usati) nelle versioni piu' recenti, <out>/fuzzer_stats in alcune
    configurazioni piu' vecchie — controlliamo entrambi.

    Anche i NOMI delle chiavi sono cambiati nel tempo (es.
    "paths_total" -> "corpus_count", "unique_crashes" -> "saved_crashes"
    in AFL++ 4.x): per ogni metrica proviamo entrambi i nomi noti.

    AGGIORNAMENTO 27/09: osservato che in modalita' "-n" (dumb mode,
    vedi run_campaign) afl-fuzz puo' NON scrivere affatto fuzzer_stats
    alla terminazione per -V (verificato su fgets_01-bad: 14 crash
    reali salvati in crashes/, plot_data aggiornato regolarmente, ma
    nessun fuzzer_stats in ne' output_dir ne' output_dir/default).
    Se manca, usiamo un fallback: contiamo direttamente i file in
    crashes/ e hangs/ (fonte primaria, sempre presente quando AFL
    trova qualcosa) e recuperiamo le altre metriche dall'ultima riga
    di plot_data, che invece viene scritto periodicamente in modo
    affidabile in entrambe le modalita'.
    """
    candidates = [output_dir / "default" / "fuzzer_stats", output_dir / "fuzzer_stats"]
    stats_path = next((p for p in candidates if p.exists()), None)

    if stats_path is not None:
        raw: dict[str, str] = {}
        for line in stats_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            raw[key.strip()] = value.strip()

        def _get_int(*keys: str) -> int:
            for k in keys:
                if k in raw:
                    try:
                        return int(float(raw[k]))
                    except ValueError:
                        continue
            return 0

        def _get_float(*keys: str) -> float:
            for k in keys:
                if k in raw:
                    try:
                        return float(raw[k])
                    except ValueError:
                        continue
            return 0.0

        return {
            "execs_done": _get_int("execs_done"),
            "execs_per_sec": _get_float("execs_per_sec"),
            "paths_total": _get_int("paths_total", "corpus_count"),
            "unique_crashes": _get_int("unique_crashes", "saved_crashes"),
            "unique_hangs": _get_int("unique_hangs", "saved_hangs"),
            "run_time": _get_int("run_time"),
            "_raw_stats_path": str(stats_path),
        }

    # --- fallback: fuzzer_stats assente ---
    base = output_dir if (output_dir / "plot_data").exists() else output_dir / "default"

    def _count_dir(name: str) -> int:
        d = base / name
        if not d.exists():
            return 0
        return sum(1 for f in d.iterdir() if f.is_file() and f.name != "README.txt")

    result = {
        "execs_done": 0,
        "execs_per_sec": 0.0,
        "paths_total": 0,
        "unique_crashes": _count_dir("crashes"),
        "unique_hangs": _count_dir("hangs"),
        "run_time": 0,
        "_raw_stats_path": f"FALLBACK (fuzzer_stats assente): conteggio diretto in {base}",
    }

    plot_path = base / "plot_data"
    if plot_path.exists():
        try:
            lines = [ln for ln in plot_path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
            if len(lines) >= 2:
                header = [h.strip().lstrip("#").strip() for h in lines[0].split(",")]
                first_row = dict(zip(header, [v.strip() for v in lines[1].split(",")]))
                last_row = dict(zip(header, [v.strip() for v in lines[-1].split(",")]))

                def _num(row: dict, *keys: str, cast=float, default=0.0):
                    for k in keys:
                        if k in row:
                            try:
                                return cast(row[k])
                            except ValueError:
                                continue
                    return default

                result["paths_total"] = int(_num(last_row, "paths_total", "corpus_count"))
                result["execs_done"] = int(_num(last_row, "execs_done"))
                result["execs_per_sec"] = _num(last_row, "execs_per_sec")
                t0 = _num(first_row, "unix_time")
                t1 = _num(last_row, "unix_time")
                if t1 > t0:
                    result["run_time"] = int(t1 - t0)
        except Exception:
            pass

    return result


def build_comparison(stats_with: dict, stats_without: dict) -> list[dict]:
    """
    Forma esattamente quella attesa da generate_report(fuzzing_effectiveness=...)
    (vedi reporting/report_generator.py e reporting/README.md).
    """
    def _row(label: str, key: str, fmt=str) -> dict:
        return {
            "metric": label,
            "with_seeds": fmt(stats_with.get(key, 0)),
            "without_seeds": fmt(stats_without.get(key, 0)),
        }

    return [
        _row("Crash trovati", "unique_crashes"),
        _row("Hang trovati", "unique_hangs"),
        _row("Percorsi unici scoperti", "paths_total"),
        _row("Esecuzioni totali", "execs_done"),
        _row("Esecuzioni al secondo", "execs_per_sec", fmt=lambda v: f"{v:.1f}"),
    ]