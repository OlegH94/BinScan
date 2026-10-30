"""
archive_campaign.py
--------------------------------------------------------------------
Archivia in blocco i risultati di una campagna completata
(bins/, sources/, ground_truth.json, selected_bins.txt, QUALUNQUE
cartella/file che inizia per "risultati", e i file di analisi/
confronto specifici prodotti dagli esperimenti su un dataset — vedi
CAMPAIGN_DATA_FILES sotto) in una cartella dedicata sotto
archive/<nome>/, lasciando l'area di lavoro del progetto pulita e
pronta per una nuova campagna — senza toccare nessuno script della
pipeline (pipe.py, main.py, vuln_scanner/, gli script *_with_claude*,
ecc. restano esattamente dove sono, si sposta solo l'output/input di
dati, mai il codice).

Perche' un pattern "risultati*" invece di un nome fisso: l'ablation
study (run_filter_ablation.py) produce PIU' cartelle di risultati
distinte (risultati_ablation_none, _basic, _refined) oltre a quella
principale — un nome fisso singolo ne lascerebbe indietro tre su
quattro. Il pattern si generalizza da solo anche a eventuali future
varianti, senza dover piu' modificare questo script ogni volta che
se ne aggiunge una nuova.

CAMPAIGN_DATA_FILES elenca invece FILE SCIOLTI (non cartelle) nella
root del progetto che sono anch'essi dati di una specifica campagna
(es. i file di confronto/verifica prodotti dagli esperimenti con
l'API Claude sui 142 binari Juliet) — a differenza di "risultati*",
questi non seguono un pattern comune riconoscibile (nomi troppo vari:
verifica_claude.md, casi_none.md, ecc.), quindi vanno elencati per
nome esatto. Aggiungere qui un nuovo nome quando si crea un nuovo
tipo di file di confronto/analisi legato a una campagna specifica.

Uso:
    python archive_campaign.py --name juliet_cwe121_142_ablation
        Archivia TUTTE le cartelle risultati*, i file fissi, e i file
        di CAMPAIGN_DATA_FILES presenti — sotto
        archive/juliet_cwe121_142_ablation/, e lascia l'area di
        lavoro pulita.

    python archive_campaign.py --list
        Elenca le campagne gia' archiviate.

    python archive_campaign.py --restore juliet_cwe121_142_ablation
        Riporta una campagna archiviata in lavorazione (rifiuta se
        l'area di lavoro non e' vuota, per non sovrascrivere nulla
        per sbaglio — usare --force per procedere comunque).
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

# Nomi fissi (sempre esattamente questi, se presenti) — cartelle/file
# che ogni campagna Juliet-style porta sempre con se'.
CAMPAIGN_FIXED_ITEMS = ["bins", "sources", "ground_truth.json", "selected_bins.txt"]

# File sciolti nella root, specifici dei risultati di UNA campagna
# (non del codice del progetto) — vedi spiegazione sopra. Aggiornare
# quando si introduce un nuovo tipo di file di analisi/confronto.
CAMPAIGN_DATA_FILES = [
    "claude_scan_juliet.json",
    "verifica_claude.md",
    "casi_none.md",
    "confronto_vulnllm.md",
    "tutti_verdetti_vulnllm.md",
]

# Pattern glob, valutati sui contenuti di primo livello della root del
# progetto — "risultati*" cattura sia "risultati" da solo sia
# "risultati_ablation_none"/"_basic"/"_refined" e qualunque variante
# futura con lo stesso prefisso.
CAMPAIGN_GLOB_PATTERNS = ["risultati*"]

ARCHIVE_ROOT = Path("archive")


def _campaign_items_present(project_root: Path) -> list[Path]:
    """Tutti gli elementi (nomi fissi + file dati + corrispondenze glob) DAVVERO presenti ora."""
    items = []

    for item_name in CAMPAIGN_FIXED_ITEMS + CAMPAIGN_DATA_FILES:
        p = project_root / item_name
        if p.exists():
            items.append(p)

    for pattern in CAMPAIGN_GLOB_PATTERNS:
        for p in sorted(project_root.glob(pattern)):
            if p not in items:
                items.append(p)

    return items


def archive_campaign(name: str, project_root: Path = Path(".")) -> None:
    archive_dir = project_root / ARCHIVE_ROOT / name

    if archive_dir.exists():
        raise FileExistsError(
            f"Esiste gia' una campagna archiviata con nome '{name}' in {archive_dir} — "
            f"scegli un nome diverso o cancella prima quella esistente se vuoi sovrascriverla."
        )

    items_to_move = _campaign_items_present(project_root)
    if not items_to_move:
        print("[=] Nessun elemento di campagna trovato nell'area di lavoro — niente da archiviare.")
        return

    archive_dir.mkdir(parents=True)

    moved = []
    for source in items_to_move:
        dest = archive_dir / source.name
        shutil.move(str(source), str(dest))
        moved.append(source.name)

    print(f"[+] Campagna archiviata in: {archive_dir}")
    print(f"[+] Spostati: {', '.join(moved)}")
    print()
    print("[+] Area di lavoro pulita — pronta per una nuova campagna.")


def list_archived_campaigns(project_root: Path = Path(".")) -> list[str]:
    archive_root = project_root / ARCHIVE_ROOT
    if not archive_root.exists():
        return []
    return sorted(d.name for d in archive_root.iterdir() if d.is_dir())


def restore_campaign(name: str, project_root: Path = Path("."), force: bool = False) -> None:
    archive_dir = project_root / ARCHIVE_ROOT / name
    if not archive_dir.exists():
        raise FileNotFoundError(f"Nessuna campagna archiviata trovata con nome '{name}' in {archive_dir}")

    archived_items = sorted(archive_dir.iterdir())

    if not force:
        already_present = [item.name for item in archived_items if (project_root / item.name).exists()]
        if already_present:
            raise FileExistsError(
                f"Nell'area di lavoro sono gia' presenti: {', '.join(already_present)} — "
                f"archivia prima la campagna corrente (--name <nome>) oppure usa --force "
                f"per sovrascriverli con quelli ripristinati."
            )

    restored = []
    for source in archived_items:
        dest = project_root / source.name
        if dest.exists():
            if dest.is_dir():
                shutil.rmtree(dest)
            else:
                dest.unlink()

        shutil.move(str(source), str(dest))
        restored.append(source.name)

    try:
        archive_dir.rmdir()
    except OSError:
        pass

    print(f"[+] Campagna '{name}' ripristinata nell'area di lavoro.")
    if restored:
        print(f"[+] Ripristinati: {', '.join(restored)}")
    else:
        print("[+] Ripristinati: nessuno trovato nell'archivio")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Archivia/ripristina una campagna completa di lavoro")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--name", metavar="NOME", help="Archivia la campagna corrente con questo nome")
    group.add_argument("--list", action="store_true", help="Elenca le campagne gia' archiviate")
    group.add_argument("--restore", metavar="NOME", help="Ripristina una campagna archiviata nell'area di lavoro")
    parser.add_argument("--force", action="store_true", help="Con --restore: sovrascrive senza chiedere conferma")
    args = parser.parse_args()

    if args.list:
        campaigns = list_archived_campaigns()
        if not campaigns:
            print("[=] Nessuna campagna archiviata trovata.")
        else:
            print(f"[*] {len(campaigns)} campagne archiviate:")
            for c in campaigns:
                print(f"    - {c}")
    elif args.name:
        archive_campaign(args.name)
    elif args.restore:
        restore_campaign(args.restore, force=args.force)