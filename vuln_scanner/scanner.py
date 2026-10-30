"""
scanner.py
--------------------------------------------------------------------
Entry point del modulo "Vulnerability Pattern Scanner" (2.3 della
pipeline di tesi), focalizzato per ora sui SOLI pattern di Buffer
Overflow (vedi yara_rules/buffer_overflow.yar).

Espone sia una funzione importabile (`run_scan`, usata da pipe.py
nella pipeline principale del progetto) sia una CLI standalone per
lanciare lo scanner da solo su un file/cartella di pseudocodice.

Flusso:
  1. legge uno o piu' file di pseudocodice C (tipicamente il
     <binario>_decompiled.c prodotto da decompiler/DecompScript.java:
     contiene gia' tutte le funzioni concatenate, formato pienamente
     compatibile con lo splitter di funzioni qui sotto)
  2. spezza il testo in funzioni
  3. per ogni funzione: esegue le regole YARA, poi per ogni match
     applica il context_analyzer (approssima le condizioni semantiche
     che YARA non esprime) e la taint_analysis (source -> sink)
  4. produce un findings.json con tutte le informazioni

Uso da CLI:
    python scanner.py --input path/al/pseudocodice --output findings.json
    python scanner.py --input path/al/pseudocodice --merge-binabsinspector report_babi.json

Uso da libreria (es. da pipe.py):
    from vuln_scanner.scanner import run_scan
    findings = run_scan(decompiled_c_path, output_json_path)
--------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yara

try:
    # import relativo quando usato come modulo del pacchetto vuln_scanner
    from .context_analyzer import analyze_match_context
    from .taint_analysis import analyze_function_taint, sink_is_tainted
except ImportError:
    # fallback per esecuzione diretta "python scanner.py" dentro la cartella
    from context_analyzer import analyze_match_context
    from taint_analysis import analyze_function_taint, sink_is_tainted

RULES_PATH = Path(__file__).parent / "yara_rules" / "buffer_overflow.yar"

# Ghidra decompilato: riconosce l'inizio di una funzione dalla firma
# tipica "tipo nome(parametri)\n{" (euristica volutamente permissiva,
# tollera anche una riga vuota tra firma e graffa, come fa Ghidra)
_FUNC_SIGNATURE_RE = re.compile(
    r"^[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*\n\{", re.MULTILINE
)

# Stringhe YARA usate SOLO per rafforzare la condizione (es. "e' dentro
# un loop", "non e' gia' safe", "c'e' un %s") ma che non rappresentano
# di per se' la riga da riportare come finding. Vedi commenti nel
# file .yar per il ruolo di ciascuna stringa in ogni regola.
_CONDITION_ONLY_STRINGS = {"$safe", "$decl", "$loop", "$fmt"}

# Ghidra scrive in cima a ogni file decompilato i PROTOTIPI delle
# funzioni di libreria esterne usate (es. "void * memcpy(void
# *__dest,void *__src,size_t __n)"), non solo le funzioni vere e
# proprie del binario. Il nostro split_into_functions() li riconosce
# come "funzioni" a tutti gli effetti (matchano la stessa firma
# regex), e se il nome del parametro non e' una costante numerica
# (es. "__n" in memcpy) le regole sul size dinamico scattano SUL
# PROTOTIPO stesso invece che su una chiamata reale nel codice del
# programma -> falso positivo strutturale, non un bug del target.
# Skippiamo quindi ogni "funzione" il cui nome coincide con una nota
# funzione di libreria: il programma da analizzare non le definisce
# mai, quindi non sono mai codice interessante da scansionare.
_KNOWN_LIBRARY_FUNCTIONS = {
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf", "gets", "fgets",
    "scanf", "sscanf", "fscanf", "__isoc99_scanf", "__isoc99_sscanf",
    "printf", "fprintf", "read", "recv", "recvfrom", "fread", "alloca",
    "malloc", "calloc", "realloc", "free", "strlen", "strnlen", "getenv",
}

# ---------------------------------------------------------------------
# Check dedicato: "size costante ma maggiore del buffer dichiarato".
#
# Le regole YARA/semgrep sul memcpy cercano size NON costanti (regex
# "non e' un numero puro"): un caso come
#   undefined1 local_28 [15];
#   memcpy(local_28, sorgente, 0x20);   // 0x20 = 32 > 15 !
# le supera entrambe, perche' 0x20 e' sintatticamente una costante
# (anche se sbagliata) — e in piu' la scritta in esadecimale (come fa
# quasi sempre Ghidra) supera anche il filtro "solo cifre decimali"
# usato per escludere le costanti nella regola semgrep. Qui invece
# leggiamo il numero vero e lo confrontiamo con la dimensione
# dichiarata dell'array destinazione nella stessa funzione: se la
# size copiata supera quella dichiarata, è un overflow verificato,
# non un'euristica — confidence sempre "high".
#
# Limitato ai tipi Ghidra a un byte per elemento (char/byte/undefined1
# e affini): per array di elementi piu' larghi (undefined4, ecc.) il
# confronto "size in byte vs lunghezza dichiarata" andrebbe moltiplicato
# per la dimensione dell'elemento, che qui non facciamo per restare
# conservativi (nessun falso positivo per una comparazione sbagliata).
# ---------------------------------------------------------------------

_BYTE_ARRAY_DECL_RE = re.compile(
    r"\b(?:undefined1|undefined|char|byte|uchar)\s+(\w+)\s*\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]"
)

# ---------------------------------------------------------------------
# check_unrolled_copy_overflow: rileva un overflow quando il COMPILATORE
# ha srotolato una memcpy/memmove in scritture dirette via puntatore
# (tipico per buffer di dimensione nota a tempo di compilazione) —
# nessuna chiamata "memcpy(...)" testualmente riconoscibile resta nel
# decompilato, solo una sequenza di assegnazioni tipo "puVar1[N] = ..."
# o "*(TIPO *)((long)ptr + N) = ...". Le regole sopra (basate sul
# trovare una CHIAMATA a memcpy/memmove) non vedono nulla in questo
# caso: serve seguire la catena di alias (fino a 2 salti di
# indirezione) dall'array dichiarato fino al puntatore usato per le
# scritture, poi sommare l'estremo piu' lontano raggiunto da qualunque
# scrittura per decidere se supera la dimensione dichiarata.
# ---------------------------------------------------------------------

_TYPE_BYTE_SIZES = {
    "undefined1": 1, "undefined": 1, "byte": 1, "char": 1, "uchar": 1,
    "undefined2": 2, "short": 2, "ushort": 2,
    "undefined4": 4, "uint": 4, "int": 4, "float": 4,
    "undefined8": 8, "ulong": 8, "long": 8, "double": 8, "size_t": 8,
}

# Dichiarazione di una variabile puntatore a un tipo noto (es.
# "undefined8 *puVar1;") — serve per sapere quanti byte occupa UN
# elemento quando quel puntatore viene indicizzato (puVar1[N]).
_PTR_DECL_RE = re.compile(r"\b(\w+)\s*\*\s*(\w+)\s*;")

# Assegnazione di alias: "alias = (TIPO *)sorgente;" o "alias = sorgente;"
# — il lookbehind negativo esclude "*alias = ..." (quella e' una SCRITTURA
# tramite puntatore, non un nuovo alias — significato completamente
# diverso nonostante la somiglianza testuale).
_ALIAS_ASSIGN_RE = re.compile(r"(?<!\*)\b(\w+)\s*=\s*(?:\(\s*[\w\s]*?\*\s*\)\s*)?(\w+)\s*;")

_INDEXED_WRITE_RE = re.compile(r"\b(\w+)\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]\s*=(?!=)")
_DEREF_WRITE_RE = re.compile(r"\*\s*(\w+)\s*=(?!=)")
_CAST_OFFSET_WRITE_RE = re.compile(
    r"\*\s*\(\s*(\w+)\s*\*\s*\)\s*\(\s*(?:\(long\)\s*)?(\w+)\s*\+\s*(0[xX][0-9a-fA-F]+|\d+)\s*\)\s*="
)

# memcpy/memmove/memset/strncpy/strncat hanno tutte la stessa forma
# posizionale (dest, src_o_valore, size) -> una sola regex le copre
# tutte. strncpy/strncat sono normalmente le "versioni sicure" di
# strcpy/strcat, ma Juliet ha varianti apposta scritte per vanificarle
# passando una size sbagliata (es. sizeof(sorgente) invece che
# sizeof(destinazione), o lo spazio gia' occupato invece di quello
# residuo per strncat): la stessa identica classe di bug del memcpy
# con sizeof(struct) invece di sizeof(campo) gia' gestito sopra.
_CONST_SIZE_COPY_RE = re.compile(
    r"\b(memcpy|memmove|memset|strncpy|strncat)\s*\(\s*&?(\w+(?:\.\w+)?)\s*,[^,]+,\s*(0[xX][0-9a-fA-F]+|\d+)\s*\)"
)

# snprintf ha un ordine argomenti diverso: (dest, size, formato, ...) —
# la size e' il SECONDO argomento, non il terzo, quindi serve una
# regex a parte invece di infilarla nell'alternanza sopra.
_CONST_SIZE_SNPRINTF_RE = re.compile(
    r"\bsnprintf\s*\(\s*&?(\w+(?:\.\w+)?)\s*,\s*(0[xX][0-9a-fA-F]+|\d+)\s*,"
)


def _parse_c_int(literal: str) -> int:
    return int(literal, 16) if literal.lower().startswith("0x") else int(literal)


def check_constant_size_overflow(func_text: str, filename: str, func_name: str) -> list[Finding]:
    declared_sizes: dict[str, int] = {}
    for m in _BYTE_ARRAY_DECL_RE.finditer(func_text):
        var_name, size_literal = m.group(1), m.group(2)
        declared_sizes[var_name] = _parse_c_int(size_literal)

    findings: list[Finding] = []
    for m in _CONST_SIZE_COPY_RE.finditer(func_text):
        call_name, dest_var, size_literal = m.group(1), m.group(2), m.group(3)
        declared = declared_sizes.get(dest_var)
        if declared is None:
            continue  # non e' un array locale a size fissa che riusciamo a leggere: non ci esprimiamo

        copy_size = _parse_c_int(size_literal)
        if copy_size <= declared:
            continue  # copia dentro i limiti dichiarati: nessun problema

        line_no = func_text.count("\n", 0, m.start()) + 1
        matched_line_text = func_text.splitlines()[line_no - 1].strip()

        findings.append(
            Finding(
                rule="BOF_Const_Size_Exceeds_Declared_Buffer",
                description=(
                    f"{call_name}() copia {copy_size} byte (costante) in '{dest_var}', "
                    f"dichiarato di soli {declared} byte: overflow verificato, non euristico"
                ),
                severity="Critical",
                cwe="CWE-121",
                function=func_name,
                file=filename,
                line=line_no,
                matched_line=matched_line_text,
                context_checked=True,
                confidence="high",
                tainted=False,
                taint_sources=[],
            )
        )

    # snprintf: stesso confronto, ma la size e' il secondo argomento
    # (regex separata perche' l'ordine posizionale e' diverso).
    for m in _CONST_SIZE_SNPRINTF_RE.finditer(func_text):
        dest_var, size_literal = m.group(1), m.group(2)
        declared = declared_sizes.get(dest_var)
        if declared is None:
            continue

        copy_size = _parse_c_int(size_literal)
        if copy_size <= declared:
            continue

        line_no = func_text.count("\n", 0, m.start()) + 1
        matched_line_text = func_text.splitlines()[line_no - 1].strip()

        findings.append(
            Finding(
                rule="BOF_Const_Size_Exceeds_Declared_Buffer",
                description=(
                    f"snprintf() usa {copy_size} come limite di scrittura su '{dest_var}', "
                    f"dichiarato di soli {declared} byte: il size hint passato e' sbagliato, "
                    f"vanifica la protezione che snprintf dovrebbe offrire"
                ),
                severity="Critical",
                cwe="CWE-121",
                function=func_name,
                file=filename,
                line=line_no,
                matched_line=matched_line_text,
                context_checked=True,
                confidence="high",
                tainted=False,
                taint_sources=[],
            )
        )
    return findings


# ---------------------------------------------------------------------
# Scrittura fuori dai limiti dentro un ciclo (Juliet: sink "loop" nelle
# categorie CWE131/CWE805/CWE806, e i "sorgente" CWE129 che alimentano
# lo stesso pattern con un indice non validato). La regola YARA
# BOF_Array_Index_No_Bound_Check si limita a segnalare "c'e' una
# scrittura indicizzata dentro un loop" — qui invece leggiamo il
# limite numerico del ciclo e lo confrontiamo con la dimensione
# dichiarata dell'array scritto, stesso principio del confronto
# numerico gia' usato per memcpy/strncpy/snprintf sopra.
#
# Limiti onesti: gestiamo solo la forma piu' comune generata da Ghidra
# per un ciclo for con contatore che parte da 0 e limite costante
# ("for (i = 0; i < N; i = i + 1)" o con "<="), e solo scritture dirette
# nella forma "array[i] = ...". Cicli con incremento diverso da 1,
# limite non costante, o indicizzazione via espressione invece che
# una singola variabile, non vengono riconosciuti — restano coperti
# solo dall'euristica grezza della regola YARA.
# ---------------------------------------------------------------------

_LOOP_HEADER_RE = re.compile(
    r"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*(<=?)\s*(0[xX][0-9a-fA-F]+|\d+)\s*;[^)]*\)\s*\{"
)


def _find_matching_brace(text: str, open_brace_pos: int) -> int:
    """Ritorna l'indice della graffa di chiusura corrispondente a quella in open_brace_pos, o -1 se non trovata."""
    depth = 0
    for i in range(open_brace_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def check_unrolled_copy_overflow(func_text: str, filename: str, func_name: str) -> list[Finding]:
    # 1. array dichiarati con dimensione nota (stessa regex delle altre regole)
    declared_sizes: dict[str, int] = {}
    for m in _BYTE_ARRAY_DECL_RE.finditer(func_text):
        declared_sizes[m.group(1)] = _parse_c_int(m.group(2))
    if not declared_sizes:
        return []

    # 2. dimensione dell'elemento puntato da ogni variabile puntatore
    #    dichiarata (serve per "ptr[N]": ogni passo N vale N*dimensione_elemento byte)
    ptr_element_size: dict[str, int] = {}
    for m in _PTR_DECL_RE.finditer(func_text):
        type_name, var_name = m.group(1), m.group(2)
        if type_name in _TYPE_BYTE_SIZES:
            ptr_element_size[var_name] = _TYPE_BYTE_SIZES[type_name]

    # 3. risoluzione alias fino a 2 salti: ogni nome che finisce per
    #    puntare (direttamente o tramite un altro alias) a un array
    #    dichiarato viene mappato al nome di QUELL'array.
    alias_to_root: dict[str, str] = {name: name for name in declared_sizes}
    for _ in range(2):
        for m in _ALIAS_ASSIGN_RE.finditer(func_text):
            lhs, rhs = m.group(1), m.group(2)
            if rhs in alias_to_root and lhs not in alias_to_root:
                alias_to_root[lhs] = alias_to_root[rhs]

    # 4. per ogni scrittura individuata tramite un alias risolto, calcola
    #    l'estremo (offset + dimensione scritta) e tiene il massimo
    #    raggiunto per ciascun array radice — una sola entry per array,
    #    anche se lo scrivono decine di istruzioni diverse.
    max_end_by_root: dict[str, int] = {}
    write_line_by_root: dict[str, int] = {}

    def _register_write(alias_name: str, offset: int, size: int, match_start: int) -> None:
        root = alias_to_root.get(alias_name)
        if root is None or root not in declared_sizes:
            return
        end = offset + size
        if end > max_end_by_root.get(root, 0):
            max_end_by_root[root] = end
            write_line_by_root[root] = match_start

    for m in _INDEXED_WRITE_RE.finditer(func_text):
        alias_name, index_literal = m.group(1), m.group(2)
        element_size = ptr_element_size.get(alias_name)
        if element_size is None:
            continue
        index = _parse_c_int(index_literal)
        _register_write(alias_name, index * element_size, element_size, m.start())

    for m in _DEREF_WRITE_RE.finditer(func_text):
        alias_name = m.group(1)
        element_size = ptr_element_size.get(alias_name)
        if element_size is None:
            continue
        _register_write(alias_name, 0, element_size, m.start())

    for m in _CAST_OFFSET_WRITE_RE.finditer(func_text):
        cast_type, alias_name, offset_literal = m.group(1), m.group(2), m.group(3)
        write_size = _TYPE_BYTE_SIZES.get(cast_type, 1)
        offset = _parse_c_int(offset_literal)
        _register_write(alias_name, offset, write_size, m.start())

    # 5. un finding per ogni array dove la scrittura massima supera la
    #    dimensione dichiarata — confidence "high": e' un confronto
    #    numerico verificato (stessa filosofia di check_constant_size_overflow),
    #    non un'euristica su un pattern testuale.
    findings: list[Finding] = []
    for root, max_end in max_end_by_root.items():
        declared = declared_sizes[root]
        if max_end <= declared:
            continue

        match_start = write_line_by_root[root]
        line_no = func_text.count("\n", 0, match_start) + 1
        matched_line_text = func_text.splitlines()[line_no - 1].strip()

        findings.append(
            Finding(
                rule="BOF_Unrolled_Copy_Exceeds_Declared_Buffer",
                description=(
                    f"Sequenza di scritture dirette via puntatore (copia srotolata dal "
                    f"compilatore) raggiunge il byte {max_end} in '{root}', dichiarato di "
                    f"soli {declared} byte: overflow verificato, non euristico"
                ),
                severity="Critical",
                cwe="CWE-121",
                function=func_name,
                file=filename,
                line=line_no,
                matched_line=matched_line_text,
                context_checked=True,
                confidence="high",
                tainted=False,
                taint_sources=[],
            )
        )

    return findings


def check_loop_bound_overflow(func_text: str, filename: str, func_name: str) -> list[Finding]:
    declared_sizes: dict[str, int] = {}
    for m in _BYTE_ARRAY_DECL_RE.finditer(func_text):
        var_name, size_literal = m.group(1), m.group(2)
        declared_sizes[var_name] = _parse_c_int(size_literal)

    findings: list[Finding] = []

    for header_match in _LOOP_HEADER_RE.finditer(func_text):
        loop_var, operator, bound_literal = header_match.groups()
        bound = _parse_c_int(bound_literal)

        body_start = header_match.end() - 1  # posizione della graffa di apertura
        body_end = _find_matching_brace(func_text, body_start)
        if body_end == -1:
            continue
        body = func_text[body_start:body_end]

        write_re = re.compile(rf"\b(\w+)\s*\[\s*{re.escape(loop_var)}\s*\]\s*=")
        for write_match in write_re.finditer(body):
            array_name = write_match.group(1)
            declared = declared_sizes.get(array_name)
            if declared is None:
                continue

            # "i < N" scrive gli indici 0..N-1 -> sicuro solo se N <= declared
            # "i <= N" scrive gli indici 0..N -> sicuro solo se N < declared
            unsafe = (operator == "<" and bound > declared) or (operator == "<=" and bound >= declared)
            if not unsafe:
                continue

            abs_offset = body_start + write_match.start()
            line_no = func_text.count("\n", 0, abs_offset) + 1
            matched_line_text = func_text.splitlines()[line_no - 1].strip()

            findings.append(
                Finding(
                    rule="BOF_Loop_Bound_Exceeds_Declared_Buffer",
                    description=(
                        f"Il ciclo scrive '{array_name}[{loop_var}]' con {loop_var} fino a {bound} "
                        f"({operator}), ma '{array_name}' e' dichiarato di soli {declared} byte: "
                        f"overflow verificato sull'ultima/e iterazione/i"
                    ),
                    severity="Critical",
                    cwe="CWE-121",
                    function=func_name,
                    file=filename,
                    line=line_no,
                    matched_line=matched_line_text,
                    context_checked=True,
                    confidence="high",
                    tainted=False,
                    taint_sources=[],
                )
            )

    return findings


@dataclass
class Finding:
    rule: str
    description: str
    severity: str
    cwe: str
    function: str
    file: str
    line: int
    matched_line: str
    context_checked: bool
    confidence: str
    tainted: bool
    taint_sources: list[str] = field(default_factory=list)


_STUB_CALL_RE = re.compile(r"\(\*\s*\(code\s*\*\)\s*PTR_")
_HALT_BADDATA_RE = re.compile(r"\bhalt_baddata\s*\(")
# Un vero stub (wrapper PTR_ o duplicato halt_baddata) ha SEMPRE 1-3
# istruzioni in tutto (dichiara, chiama, ritorna) — MAI di piu'. Senza
# questa soglia, una funzione vulnerabile vera che chiama alloca()
# (decompilato da Ghidra con lo stesso pattern PTR_ usato per gli
# stub esterni, ma qui dentro una funzione con molta altra logica)
# verrebbe scartata per intero.
_MAX_STUB_STATEMENTS = 4


def _is_pure_stub(body: str) -> bool:
    if not (_STUB_CALL_RE.search(body) or _HALT_BADDATA_RE.search(body)):
        return False
    return body.count(";") <= _MAX_STUB_STATEMENTS


# Livello di filtro delle funzioni-stub, per l'esperimento di
# ablation study (Capitolo 6 di tesi): quanto pulire lo pseudocodice
# prima della scansione. Letto da variabile d'ambiente per non dover
# toccare pipe.py — se non impostata, comportamento identico a prima
# di questo esperimento (REFINED).
FILTER_LEVEL_NONE = "none"        # nessun filtro: scansiona anche stub PTR_ e duplicati halt_baddata
FILTER_LEVEL_BASIC = "basic"      # solo la lista fissa _KNOWN_LIBRARY_FUNCTIONS
FILTER_LEVEL_REFINED = "refined"  # lista fissa + controllo strutturale con soglia (default)

_FILTER_LEVEL_ENV_VAR = "VULN_SCANNER_FILTER_LEVEL"


def _get_filter_level() -> str:
    return os.environ.get(_FILTER_LEVEL_ENV_VAR, FILTER_LEVEL_REFINED)


def split_into_functions(source_text: str, filename: str) -> list[tuple[str, str, int]]:
    """
    Ritorna una lista di (nome_funzione, testo_funzione, offset_iniziale_nel_file).
    Se non riesce a individuare confini di funzione, tratta l'intero
    file come un'unica "funzione" chiamata come il file stesso.
    """
    matches = list(_FUNC_SIGNATURE_RE.finditer(source_text))
    if not matches:
        return [(filename, source_text, 0)]

    functions = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source_text)
        name = m.group(1)
        functions.append((name, source_text[start:end], start))
    return functions


def scan_text(source_text: str, filename: str, rules: "yara.Rules") -> list[Finding]:
    findings: list[Finding] = []
    filter_level = _get_filter_level()

    for func_name, func_text, func_offset in split_into_functions(source_text, filename):
        if filter_level != FILTER_LEVEL_NONE and func_name in _KNOWN_LIBRARY_FUNCTIONS:
            continue
        if filter_level == FILTER_LEVEL_REFINED and _is_pure_stub(func_text):
            continue

        findings.extend(check_constant_size_overflow(func_text, filename, func_name))
        findings.extend(check_unrolled_copy_overflow(func_text, filename, func_name))
        findings.extend(check_loop_bound_overflow(func_text, filename, func_name))

        matches = rules.match(data=func_text)
        if not matches:
            continue

        taint_map = analyze_function_taint(func_text)

        for rule_match in matches:
            meta = rule_match.meta
            severity = meta.get("severity", "Medium")
            description = meta.get("description", rule_match.rule)
            cwe = meta.get("cwe", "")

            for string_match in rule_match.strings:
                if string_match.identifier in _CONDITION_ONLY_STRINGS:
                    continue
                for instance in string_match.instances:
                    offset = instance.offset
                    matched_line_no = func_text.count("\n", 0, offset) + 1
                    matched_line_text = func_text.splitlines()[matched_line_no - 1].strip()

                    ctx = analyze_match_context(func_text, offset, severity)
                    is_tainted, sources = sink_is_tainted(matched_line_text, taint_map)

                    findings.append(
                        Finding(
                            rule=rule_match.rule,
                            description=description,
                            severity=severity,
                            cwe=cwe,
                            function=func_name,
                            file=filename,
                            line=matched_line_no,
                            matched_line=matched_line_text,
                            context_checked=ctx.context_checked,
                            confidence=ctx.confidence,
                            tainted=is_tainted,
                            taint_sources=sources,
                        )
                    )
    return findings


def scan_path(input_path: Path, rules: "yara.Rules") -> list[Finding]:
    all_findings: list[Finding] = []
    input_path = Path(input_path)
    files = [input_path] if input_path.is_file() else sorted(input_path.rglob("*.c"))

    if not files:
        print(f"[!] Nessun file .c trovato in {input_path}", file=sys.stderr)

    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        all_findings.extend(scan_text(text, f.name, rules))

    return all_findings


def merge_binabsinspector(findings: list[Finding], babi_report_path: Path) -> list[dict]:
    """
    Unisce i finding YARA+taint con un report esportato da
    BinAbsInspector (JSON). Il formato esatto dell'export dipende
    dalla versione dell'estensione: qui ci si aspetta una lista di
    oggetti con almeno {"function": ..., "line": ..., "cwe": ..., "description": ...}
    (adatta la funzione se la tua versione usa chiavi diverse).
    """
    babi_raw = json.loads(Path(babi_report_path).read_text(encoding="utf-8"))
    babi_findings = babi_raw if isinstance(babi_raw, list) else babi_raw.get("findings", [])

    merged = [asdict(f) for f in findings]
    used_babi_idx = set()

    for f in merged:
        for i, b in enumerate(babi_findings):
            if i in used_babi_idx:
                continue
            same_func = str(b.get("function", "")).strip() == f["function"]
            same_line = int(b.get("line", -1)) == f["line"]
            if same_func and same_line:
                f["confirmed_by_binabsinspector"] = True
                f["binabsinspector_cwe"] = b.get("cwe")
                used_babi_idx.add(i)
                break
        else:
            f["confirmed_by_binabsinspector"] = False

    only_babi = [
        {**b, "source": "binabsinspector_only"}
        for i, b in enumerate(babi_findings)
        if i not in used_babi_idx
    ]

    return merged + only_babi


def run_scan(
    input_path: str | Path,
    output_json: str | Path,
    rules_path: str | Path = RULES_PATH,
    babi_report_path: str | Path | None = None,
) -> list[Finding]:
    """
    Interfaccia pensata per essere chiamata da pipe.py (o da qualunque
    altro script) senza passare da subprocess/CLI.

    Scansiona `input_path` (file o cartella di pseudocodice .c),
    scrive il risultato in `output_json` (creando le cartelle
    mancanti) e ritorna la lista di Finding.
    """
    rules = yara.compile(filepath=str(rules_path))
    findings = scan_path(Path(input_path), rules)

    output_json = Path(output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)

    if babi_report_path:
        output_data = merge_binabsinspector(findings, Path(babi_report_path))
    else:
        output_data = [asdict(f) for f in findings]

    output_json.write_text(json.dumps(output_data, indent=2, ensure_ascii=False), encoding="utf-8")

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Vulnerability Pattern Scanner - Buffer Overflow")
    parser.add_argument("--input", required=True, help="File o cartella con pseudocodice Ghidra (.c)")
    parser.add_argument("--output", default="findings.json", help="File JSON di output")
    parser.add_argument("--rules", default=str(RULES_PATH), help="Path alle regole YARA")
    parser.add_argument(
        "--merge-binabsinspector",
        dest="babi_report",
        default=None,
        help="Path al report JSON esportato da BinAbsInspector, da fondere con i risultati",
    )
    args = parser.parse_args()

    findings = run_scan(args.input, args.output, args.rules, args.babi_report)

    print(f"[+] {len(findings)} finding individuati.")
    print(f"[+] Output scritto in {args.output}")

    high_conf = [f for f in findings if f.tainted and f.confidence in ("high", "medium")]
    if high_conf:
        print(f"[!] {len(high_conf)} finding con taint confermato e confidenza medio/alta:")
        for f in high_conf:
            print(f"    - {f.file}:{f.function}:{f.line} [{f.rule}] {f.matched_line}")


if __name__ == "__main__":
    main()