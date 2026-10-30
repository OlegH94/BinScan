"""
code_context.py
--------------------------------------------------------------------
Estrae il testo completo di una funzione (per NOME) da un blob di
codice C — sia esso pseudocodice decompilato da Ghidra o sorgente
originale — per mostrarlo nel report al posto di un semplice numero
di riga.

Perche' non ci basiamo sul numero di riga per individuare il punto
esatto (oltre al motivo gia' discusso in accuracy.py: i numeri di
riga tra sorgente e decompilato raramente corrispondono comunque):
il pseudocodice generato da Ghidra contiene spesso righe vuote tra la
firma della funzione e la parentesi graffa di apertura, e tra le
dichiarazioni delle variabili locali. Questo significa che anche il
numero di riga riportato DIRETTAMENTE DA GHIDRA in un finding puo'
risultare disallineato rispetto a un conteggio "riga per riga" fatto
aprendo lo stesso testo in un editor con regole di wrapping/rendering
leggermente diverse. Individuare la funzione per nome (la stessa
strategia gia' usata da accuracy.py e da
juliet_ground_truth_importer.py per il confronto con la ground truth)
e mostrarne il corpo intero elimina il problema alla radice: non
serve piu' che un numero di riga sia "giusto", basta che il nome
funzione lo sia.
--------------------------------------------------------------------
"""

from __future__ import annotations

import re

# Stessa firma di funzione usata in juliet_ground_truth_importer.py:
# permissiva sulla posizione della graffa di apertura (stessa riga
# della firma, o su una riga separata con eventuali righe vuote in
# mezzo - comune nel pseudocodice Ghidra, vedi il docstring sopra).
_FUNC_SIGNATURE_RE = re.compile(
    r"^[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*\{", re.MULTILINE
)

# Come in juliet_ground_truth_importer.py: la regex sopra e'
# sintatticamente indistinguibile da uno statement di controllo
# ("if (...) {", "for (...) {", ...): li scartiamo esplicitamente,
# altrimenti si rischia di individuare un blocco if invece della vera
# funzione (bug reale gia' incontrato altrove nel progetto).
_C_CONTROL_KEYWORDS = {"if", "else", "for", "while", "switch", "do", "return", "sizeof"}


def _find_matching_brace(text: str, open_brace_pos: int) -> int | None:
    """
    A partire dalla posizione di una '{' (inclusa), trova la posizione
    della '}' che la chiude, contando le graffe annidate e ignorando
    quelle dentro stringhe, char literal o commenti (per non
    confondersi con una graffa scritta come carattere letterale o
    dentro un commento).

    Ritorna None se il testo finisce prima di trovare la chiusura
    (file troncato o estrazione malformata): meglio segnalarlo con un
    None esplicito che restituire un frammento a meta'.
    """
    depth = 0
    i = open_brace_pos
    in_string = in_char = in_line_comment = in_block_comment = False

    while i < len(text):
        c = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_line_comment:
            if c == "\n":
                in_line_comment = False
        elif in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_string:
            if c == "\\":
                i += 1
            elif c == '"':
                in_string = False
        elif in_char:
            if c == "\\":
                i += 1
            elif c == "'":
                in_char = False
        else:
            if c == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif c == "/" and nxt == "*":
                in_block_comment = True
                i += 1
            elif c == '"':
                in_string = True
            elif c == "'":
                in_char = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i

        i += 1

    return None


def extract_function_code(text: str | None, function_name: str | None) -> str | None:
    """
    Ritorna il testo completo della funzione `function_name` dentro
    `text` (dalla firma alla graffa di chiusura inclusa), o None se
    `text`/`function_name` sono vuoti o la funzione non viene trovata.

    Se ci sono piu' funzioni con lo stesso nome nel testo (es. sorgenti
    Juliet a due file "a.c"/"b.c" concatenati, dove capita che un nome
    ricorra), ritorna la prima trovata: nella pratica di questo
    progetto i nomi di funzione nei binari Juliet sono gia' univoci
    per binario (e' proprio l'assunzione su cui si basa accuracy.py),
    quindi il caso ambiguo non dovrebbe presentarsi.
    """
    if not text or not function_name:
        return None

    for m in _FUNC_SIGNATURE_RE.finditer(text):
        if m.group(1) != function_name or m.group(1) in _C_CONTROL_KEYWORDS:
            continue

        open_brace_pos = m.end() - 1  # l'ultimo carattere del match e' la '{'
        close_pos = _find_matching_brace(text, open_brace_pos)
        snippet = text[m.start():] if close_pos is None else text[m.start():close_pos + 1]

        # Il prefisso non-goloso della regex ([\w\*\s]+?) puo' "risalire"
        # oltre righe vuote precedenti (es. la riga vuota di separazione
        # dalla funzione precedente, tipica del pseudocodice Ghidra),
        # finendo dentro il match. Tagliamo solo le righe vuote INIZIALI
        # cosi' assorbite: le righe vuote interne alla funzione (tra
        # firma e graffa, tra le dichiarazioni, ecc.) restano intatte,
        # sono normale formattazione Ghidra, non un artefatto del match.
        return snippet.lstrip("\n")

    return None


def find_function_start_line(text: str | None, function_name: str | None) -> int | None:
    """
    Ritorna il numero di riga (1-based) a cui inizia la firma della
    funzione `function_name` dentro `text`, o None se non trovata.
    Usato per costruire un link di ancora ("#L42") dal frammento
    mostrato accanto a un finding alla pagina con il file completo.
    """
    if not text or not function_name:
        return None

    for m in _FUNC_SIGNATURE_RE.finditer(text):
        if m.group(1) != function_name or m.group(1) in _C_CONTROL_KEYWORDS:
            continue
        # Usiamo m.start(1) (l'inizio del nome funzione catturato),
        # non m.start() (l'inizio dell'intero match): il prefisso non
        # goloso puo' assorbire righe vuote precedenti (stesso motivo
        # per cui extract_function_code applica lstrip("\n") sul
        # risultato), spostando m.start() su una riga vuota precedente
        # invece che sulla riga reale della firma.
        return text.count("\n", 0, m.start(1)) + 1

    return None


def all_lines_numbered(text: str | None, highlight_set: set[str] | None = None) -> list[dict]:
    """
    Spezza l'intero `text` in righe numerate (1-based) per la pagina
    "file completo": ogni riga ha un numero (per l'ancora "#L{n}" nei
    link) ed e' marcata "highlight" se il suo contenuto spogliato
    coincide con una delle stringhe in `highlight_set` (tipicamente
    l'insieme di tutti i `matched_line` dei finding di questo binario,
    cosi' aprendo il file intero si vede subito, evidenziato in
    posizione, ogni punto che ha fatto scattare un finding — utile
    anche solo per farsi un'idea generale del codice, a prescindere
    dal fatto che un finding specifico sia stato trovato o meno).
    """
    if not text:
        return []

    highlight_set = highlight_set or set()
    lines = []
    for i, line in enumerate(text.splitlines(), start=1):
        lines.append({
            "n": i,
            "text": line,
            "highlight": line.strip() in highlight_set if line.strip() else False,
        })
    return lines


def code_lines_with_highlight(code: str | None, matched_line: str | None) -> list[dict]:
    """
    Spezza `code` in righe per il template, marcando come "highlight"
    la prima riga il cui contenuto (spazi iniziali/finali a parte)
    coincide con `matched_line` - la riga esatta che ha fatto scattare
    il finding - cosi' resta individuabile a colpo d'occhio anche
    dentro una funzione di decine di righe, senza dover contare
    numeri di riga.

    Ritorna una lista vuota se `code` e' vuoto (comodo per i template:
    "{% if f.decompiled_lines %}" e' gia' False su lista vuota).
    """
    if not code:
        return []

    matched_stripped = matched_line.strip() if matched_line else None
    already_highlighted = False
    lines = []
    for line in code.splitlines():
        is_match = (
            not already_highlighted
            and matched_stripped is not None
            and line.strip() == matched_stripped
        )
        if is_match:
            already_highlighted = True
        lines.append({"text": line, "highlight": is_match})
    return lines