/*
 * ghidra_types.h
 * ------------------------------------------------------------------
 * Lo pseudocodice C emesso da Ghidra (DecompInterface.getC()) usa
 * una manciata di typedef propri di Ghidra (undefined4, uint, code,
 * ...) che non fanno parte del C standard. Un parser "vero" come
 * quello di semgrep (basato su tree-sitter, non su regex come YARA)
 * ha bisogno che questi tipi siano dichiarati da qualche parte per
 * poter costruire un AST valido — altrimenti fallisce silenziosamente
 * il parsing di intere funzioni.
 *
 * Questo header viene anteposto in memoria al file di pseudocodice
 * prima di passarlo a semgrep (vedi semgrep_scanner.py:
 * _prepend_ghidra_header). Non va MAI scritto su disco dentro
 * decompiled_files/: e' solo un prefisso temporaneo usato per il
 * parsing, gli offset di riga vengono poi corretti sottraendo il
 * numero di righe di questo header.
 * ------------------------------------------------------------------
 */

typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ulonglong;
typedef long long longlong;

typedef unsigned char byte;
typedef unsigned char uint1;
typedef unsigned short uint2;
typedef unsigned int uint4;
typedef unsigned long long uint8;

typedef void code;
