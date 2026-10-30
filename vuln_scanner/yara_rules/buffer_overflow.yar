/*
 * buffer_overflow.yar
 * ------------------------------------------------------------------
 * Regole YARA per l'individuazione di pattern di Buffer Overflow su
 * pseudocodice C decompilato da Ghidra.
 *
 * IMPORTANTE (vedi README.md, sezione "Perche' YARA da solo non basta"):
 * YARA riconosce solo pattern testuali/regex, NON puo' esprimere
 * condizioni semantiche come "manca un controllo di dimensione a monte".
 * Per questo ogni regola qui sotto individua il CANDIDATO pericoloso
 * (la chiamata/il pattern), mentre la verifica "manca il size check"
 * viene fatta a valle da context_analyzer.py sulla funzione che
 * contiene il match. Il campo `severity` e `cwe` nei meta sono
 * convenzioni lette dal nostro scanner, non sintassi nativa YARA.
 * ------------------------------------------------------------------
 */

rule BOF_Unbounded_Strcpy
{
    meta:
        description = "Uso di strcpy senza controllo di dimensione"
        severity = "High"
        cwe = "CWE-120"
        category = "buffer_overflow"

    strings:
        $call = /\bstrcpy\s*\([^,]+,[^)]+\)/

    condition:
        $call
}

rule BOF_Unbounded_Strcat
{
    meta:
        description = "Uso di strcat senza controllo di dimensione residua"
        severity = "High"
        cwe = "CWE-120"
        category = "buffer_overflow"

    strings:
        $call = /\bstrcat\s*\([^,]+,[^)]+\)/

    condition:
        $call
}

rule BOF_Gets_Call
{
    meta:
        description = "Uso di gets(), intrinsecamente non delimitabile"
        severity = "Critical"
        cwe = "CWE-242"
        category = "buffer_overflow"

    strings:
        $call = /\bgets\s*\(/

    condition:
        $call
}

rule BOF_Sprintf_No_Bound
{
    meta:
        description = "Uso di sprintf invece di snprintf (nessun limite sulla destinazione)"
        severity = "High"
        cwe = "CWE-120"
        category = "buffer_overflow"

    strings:
        $call = /\bsprintf\s*\(/

    condition:
        // NOTA: la vecchia condizione ('$call and not $safe', dove $safe
        // cercava snprintf() ovunque nella stessa funzione) presupponeva
        // che la presenza di UN QUALSIASI snprintf rendesse sicuro OGNI
        // sprintf nella stessa funzione — falso su funzioni reali con piu'
        // operazioni buffer indipendenti (bug reale scoperto validando su
        // CVE-2021-20294/readelf: print_dynamic_symbol usa 4 snprintf
        // sicuri E 1 sprintf pericoloso, la vecchia condizione silenziava
        // la regola per intero). YARA non supporta una correlazione
        // per-singola-chiamata, quindi si accetta di far scattare la
        // regola su OGNI sprintf, a costo di qualche falso positivo in
        // piu' sui rari casi in cui un singolo sprintf isolato sia
        // genuinamente al sicuro (es. formato letterale di dimensione
        // nota staticamente).
        $call
}

rule BOF_Vsprintf_No_Bound
{
    meta:
        description = "Uso di vsprintf invece di vsnprintf"
        severity = "High"
        cwe = "CWE-120"
        category = "buffer_overflow"

    strings:
        $call = /\bvsprintf\s*\(/

    condition:
        $call
}

rule BOF_Memcpy_Suspicious_Size
{
    meta:
        description = "memcpy con size che proviene da variabile/espressione (potenziale mismatch col buffer destinazione)"
        severity = "Medium"
        cwe = "CWE-787"
        category = "buffer_overflow"

    strings:
        // terzo argomento NON e' una costante numerica pura -> size dinamica
        $call = /\bmemcpy\s*\([^,]+,[^,]+,\s*[^0-9\s][^)]*\)/

    condition:
        $call
}

rule BOF_Memmove_Suspicious_Size
{
    meta:
        description = "memmove con size dinamica"
        severity = "Medium"
        cwe = "CWE-787"
        category = "buffer_overflow"

    strings:
        $call = /\bmemmove\s*\([^,]+,[^,]+,\s*[^0-9\s][^)]*\)/

    condition:
        $call
}

rule BOF_Strncpy_Suspicious_Size
{
    meta:
        description = "strncpy con size che proviene da variabile/espressione (Juliet CWE-121: spesso usato apposta col size sbagliato, es. sizeof(sorgente) invece di sizeof(destinazione))"
        severity = "Medium"
        cwe = "CWE-121"
        category = "buffer_overflow"

    strings:
        $call = /\bstrncpy\s*\([^,]+,[^,]+,\s*[^0-9\s][^)]*\)/

    condition:
        $call
}

rule BOF_Strncat_Suspicious_Size
{
    meta:
        description = "strncat con size che proviene da variabile/espressione (stesso pattern di misuso di strncpy: la size dovrebbe riferirsi allo spazio RESIDUO nella destinazione, non a sizeof(sorgente))"
        severity = "Medium"
        cwe = "CWE-121"
        category = "buffer_overflow"

    strings:
        $call = /\bstrncat\s*\([^,]+,[^,]+,\s*[^0-9\s][^)]*\)/

    condition:
        $call
}

rule BOF_Snprintf_Suspicious_Size
{
    meta:
        description = "snprintf con size che proviene da variabile/espressione (di norma la funzione 'sicura', ma se la size passata non corrisponde alla destinazione il vantaggio si annulla)"
        severity = "Medium"
        cwe = "CWE-121"
        category = "buffer_overflow"

    strings:
        $call = /\bsnprintf\s*\([^,]+,\s*[^0-9\s][^,]*,/

    condition:
        $call
}

rule BOF_Scanf_Unbounded_String
{
    meta:
        description = "scanf/sscanf/fscanf con %s senza specificatore di larghezza campo"
        severity = "High"
        cwe = "CWE-120"
        category = "buffer_overflow"

    strings:
        // %s non preceduto da un numero (larghezza massima), es. "%s" invece di "%63s"
        $fmt = /%s/
        $call = /\b(scanf|sscanf|fscanf|__isoc99_scanf|__isoc99_sscanf)\s*\(/

    condition:
        $call and $fmt and not /%[0-9]+s/
}

rule BOF_Stack_Buffer_Plus_Read
{
    meta:
        description = "Buffer locale su stack seguito da read()/recv() con size non correlata alla dichiarazione"
        severity = "Medium"
        cwe = "CWE-121"
        category = "buffer_overflow"

    strings:
        $decl = /\bchar\s+\w+\s*\[\s*[0-9]+\s*\]/
        $read = /\b(read|recv)\s*\(/

    condition:
        $decl and $read
}

rule BOF_Alloca_Dynamic_Size
{
    meta:
        description = "alloca()/array a lunghezza variabile (VLA) con size non costante"
        severity = "Medium"
        cwe = "CWE-131"
        category = "buffer_overflow"

    strings:
        $alloca = /\balloca\s*\(\s*[^0-9\s][^)]*\)/

    condition:
        $alloca
}

rule BOF_Array_Index_No_Bound_Check
{
    meta:
        description = "Scrittura in array indicizzato da variabile dentro un ciclo, senza confronto esplicito col limite nella stessa riga (euristica grezza: per un confronto numerico preciso vedi check_loop_bound_overflow() in scanner.py)"
        severity = "Low"
        cwe = "CWE-787"
        category = "buffer_overflow"

    strings:
        // scrittura tipo buf[i] = ... dentro un for/while. Il \b iniziale
        // e' necessario: senza, YARA la fa matchare ripetutamente su ogni
        // sotto-stringa che inizia da un carattere diverso della stessa
        // identica scrittura (es. "dest[i]=", "est[i]=", "st[i]=", "t[i]="
        // tutti soddisfano \w+\s*\[ senza l'ancora) - bug scoperto scrivendo
        // il test per check_loop_bound_overflow().
        $write = /\b\w+\s*\[\s*\w+\s*\]\s*=/
        $loop  = /\b(for|while)\s*\(/

    condition:
        $write and $loop
}

rule BOF_Format_String_To_Buffer
{
    meta:
        description = "Format string potenzialmente controllata da input passata come primo argomento a *printf (puo' portare a overflow o a leak/scrittura arbitraria)"
        severity = "Medium"
        cwe = "CWE-134"
        category = "buffer_overflow"

    strings:
        // printf-like call il cui primo argomento non e' una stringa letterale (") ma una variabile
        $call = /\b(printf|fprintf|sprintf|snprintf)\s*\(\s*[a-zA-Z_]\w*\s*[,\)]/

    condition:
        $call
}
