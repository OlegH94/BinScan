#!/usr/bin/env python3
"""
Controlla, tra le cartelle archiviate/risultati di BinScan, quali binari
hanno già dati di fuzzing pronti (seed generati, harness non-socket)
e quindi sono buoni candidati per una nuova run di fuzzing pulita
senza dover ricostruire nulla da zero.

Uso:
    python check_fuzzing_ready.py [cartella_radice]

Se non specifichi una cartella, usa la directory corrente.
Cerca in TUTTE le sottocartelle che iniziano con "risultati" o "archive"
o "archivio", più eventuali cartelle top-level con "fuzzing" dentro.
"""
import sys
import json
from pathlib import Path


def find_candidate_roots(base: Path):
    roots = []
    for p in base.iterdir():
        if not p.is_dir():
            continue
        name = p.name.lower()
        if name.startswith("risultati") or "archiv" in name:
            roots.append(p)
    # anche la base stessa, se ha binari diretti dentro
    roots.append(base)
    return roots


def inspect_binary_dir(bin_dir: Path):
    """Ritorna un dict di stato per una singola cartella-binario dentro risultati*/"""
    info = {
        "path": str(bin_dir),
        "has_fuzzing_dir": False,
        "seed_dirs": [],
        "seed_counts": {},
        "afl_output_present": False,
        "looks_socket_based": None,  # None = non determinato, True/False altrimenti
        "harness_hint": None,
    }

    fuzz_dir = bin_dir / "fuzzing"
    if not fuzz_dir.is_dir():
        return info
    info["has_fuzzing_dir"] = True

    for sub in fuzz_dir.iterdir():
        if sub.is_dir() and "seed" in sub.name.lower():
            count = sum(1 for f in sub.iterdir() if f.is_file())
            info["seed_dirs"].append(sub.name)
            info["seed_counts"][sub.name] = count
        if sub.is_dir() and ("afl_out" in sub.name.lower() or "out" == sub.name.lower()):
            info["afl_output_present"] = True

    # euristica: cerca menzioni di socket/recv/connect nei sorgenti associati (se presenti)
    src_hits = []
    for src_candidate in [bin_dir.parent.parent / "sources", bin_dir.parent / "sources"]:
        if src_candidate.is_dir():
            for f in src_candidate.glob(f"*{bin_dir.name.split('-')[0]}*"):
                try:
                    text = f.read_text(errors="ignore")
                except Exception:
                    continue
                if any(k in text for k in ("recv(", "connect(", "accept(", "listen(")):
                    src_hits.append(f.name)
    if src_hits:
        info["looks_socket_based"] = True
        info["harness_hint"] = f"input via socket (trovato in: {', '.join(src_hits[:3])})"
    elif info["has_fuzzing_dir"]:
        info["looks_socket_based"] = False
        info["harness_hint"] = "nessun indizio di socket nei sorgenti trovati (probabile stdin/file/argv)"

    return info


def main():
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    base = base.resolve()
    if not base.is_dir():
        print(f"[!] Cartella non trovata: {base}")
        sys.exit(1)

    print(f"[*] Scansione a partire da: {base}\n")

    roots = find_candidate_roots(base)
    seen = set()
    results = []

    for root in roots:
        if not root.is_dir():
            continue
        for bin_dir in root.iterdir():
            if not bin_dir.is_dir():
                continue
            key = bin_dir.resolve()
            if key in seen:
                continue
            seen.add(key)
            info = inspect_binary_dir(bin_dir)
            if info["has_fuzzing_dir"]:
                results.append(info)

    if not results:
        print("[!] Nessuna cartella con dati di fuzzing trovata sotto le radici cercate.")
        print("    Radici controllate:", [str(r) for r in roots])
        return

    print(f"[*] Trovate {len(results)} cartelle-binario con dati di fuzzing:\n")
    for info in sorted(results, key=lambda x: x["path"]):
        name = Path(info["path"]).name
        socket_flag = "SOCKET (probabile problema)" if info["looks_socket_based"] else (
            "stdin/file/argv (OK)" if info["looks_socket_based"] is False else "?"
        )
        seed_summary = ", ".join(
            f"{d}={info['seed_counts'].get(d, 0)}" for d in info["seed_dirs"]
        ) or "nessun seed_dir"
        print(f"  - {name}")
        print(f"      seed: {seed_summary}")
        print(f"      afl_output presente: {info['afl_output_present']}")
        print(f"      input type: {socket_flag}")
        if info["harness_hint"]:
            print(f"      hint: {info['harness_hint']}")
        print()

    # riepilogo finale: candidati "puliti" (no socket, con seed)
    clean = [
        Path(i["path"]).name for i in results
        if i["looks_socket_based"] is False and any(c > 0 for c in i["seed_counts"].values())
    ]
    print("=" * 60)
    print("CANDIDATI PULITI per nuova run di fuzzing (no socket, seed presenti):")
    if clean:
        for c in clean:
            print(f"  -> {c}")
    else:
        print("  (nessuno trovato automaticamente — verifica manualmente)")


if __name__ == "__main__":
    main()