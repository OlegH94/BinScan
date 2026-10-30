"""
package_for_colab.py
--------------------------------------------------------------------
Impacchetta in un unico zip i file necessari alla revisione LLM su
Colab, con la struttura di cartelle che il notebook si aspetta:

    input/
      <nome_bin_1>/
        decompiled.c              (obbligatorio)
        findings_all.json         (opzionale, se presente)
        callgraph_named.graphml   (opzionale, se presente)
      <nome_bin_2>/
        ...

Uso:
    python package_for_colab.py                          # tutti i binari in risultati/
    python package_for_colab.py --from-file affected_bins.txt   # solo alcuni
    python package_for_colab.py --only NOME_BIN           # solo uno
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import shutil
import zipfile
from pathlib import Path

RISULTATI_DIR = Path("risultati")
OUTPUT_ZIP = Path("colab_input.zip")


def _discover_all_binaries(risultati_dir: Path) -> list[str]:
    return sorted(
        d.name for d in risultati_dir.iterdir()
        if d.is_dir() and (d / "decompiled_files").exists()
    )


def package(binary_names: list[str], risultati_dir: Path, output_zip: Path) -> None:
    staging = Path("_colab_staging")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()

    packaged = 0
    for binary_name in binary_names:
        decompiled_c = risultati_dir / binary_name / "decompiled_files" / f"{binary_name}_decompiled.c"
        if not decompiled_c.exists():
            print(f"[!] {binary_name}: decompiled.c non trovato, salto")
            continue

        dest_dir = staging / "input" / binary_name
        dest_dir.mkdir(parents=True)
        shutil.copy2(decompiled_c, dest_dir / "decompiled.c")

        findings = risultati_dir / binary_name / "vuln_scanner" / "findings_all.json"
        if findings.exists():
            shutil.copy2(findings, dest_dir / "findings_all.json")

        callgraph = risultati_dir / binary_name / "CFG" / "callgraph_named.graphml"
        if callgraph.exists():
            shutil.copy2(callgraph, dest_dir / "callgraph_named.graphml")

        packaged += 1

    if output_zip.exists():
        output_zip.unlink()

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in staging.rglob("*"):
            if file_path.is_file():
                zf.write(file_path, file_path.relative_to(staging))

    shutil.rmtree(staging)

    print(f"[+] {packaged} binari impacchettati -> {output_zip}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Impacchetta i decompiled.c per la revisione LLM su Colab")
    parser.add_argument("--only", metavar="NOME_BIN", default=None)
    parser.add_argument("--from-file", metavar="PATH", default=None,
                         help="File con un nome binario per riga (es. affected_bins.txt)")
    parser.add_argument("--risultati-dir", default=str(RISULTATI_DIR))
    parser.add_argument("--output", default=str(OUTPUT_ZIP))
    args = parser.parse_args()

    risultati_dir = Path(args.risultati_dir)

    if args.only:
        names = [args.only]
    elif args.from_file:
        names = [
            line.strip() for line in Path(args.from_file).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        names = _discover_all_binaries(risultati_dir)

    package(names, risultati_dir, Path(args.output))