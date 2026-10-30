#!/usr/bin/env python3
"""
Smart Unpacking Engine - Rilevamento e unpacking automatico di file PE/ELF
Supporta: rilevamento tipo file, analisi entropia, unpacking con Unipacker
"""

import math
import os
import subprocess
from collections import Counter
from typing import Tuple
from pathlib import Path
import io

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("[!] pefile non installato. Installa: pip install pefile")

try:
    from elftools.elf.elffile import ELFFile

    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False
    print("[!] pyelftools non installato. Installa: pip install pyelftools")


# ============================================================================
# FUNZIONI DI UTILITÀ
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calcola l'entropia di Shannon dei byte del file.
    Entropia alta (>6.5) indica potenziale compressione/packing.

    Args:
        data: Contenuto del file in bytes

    Returns:
        Valore di entropia (0.0 - 8.0)
    """
    if not data:
        return 0.0

    # Usa Counter per efficienza - O(n) invece di O(256*n)
    byte_counts = Counter(data)
    entropy = 0.0
    data_len = len(data)

    for count in byte_counts.values():
        p_x = count / data_len
        entropy -= p_x * math.log2(p_x)

    return entropy


def detect_type(filepath: str) -> str:
    """
    Rileva il tipo di file tramite magic bytes.

    Args:
        filepath: Percorso del file

    Returns:
        "PE" (Windows), "ELF" (Linux/Unix), o "UNKNOWN"
    """
    try:
        if not os.path.exists(filepath):
            print(f"[-] File non trovato: {filepath}")
            return "UNKNOWN"

        with open(filepath, "rb") as f:
            magic = f.read(4)

        if magic.startswith(b"MZ"):
            return "PE"
        elif magic.startswith(b"\x7fELF"):
            return "ELF"
        else:
            return "UNKNOWN"

    except Exception as e:
        print(f"[-] Errore nella rilevazione del tipo: {e}")
        return "UNKNOWN"


def is_likely_packed(filepath: str) -> Tuple[bool, dict]:
    """
    Rilevamento euristico di file packed per PE ed ELF.

    Controlla:
    1. Entropia generale (soglia: >6.5)
    2. Sezioni sospette (PE): UPX, ASPACK, PECOMPACT, THEMIDA, etc.
    3. Sezioni sospette (ELF): UPX

    Args:
        filepath: Percorso del file

    Returns:
        (bool, dict): (è_packed, info_dettagli)
    """
    ftype = detect_type(filepath)
    info = {
        "type": ftype,
        "entropy": 0.0,
        "packed_indicators": [],
        "confidence": 0.0
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Errore nella lettura del file: {e}")
        return False, info

    # 1. CONTROLLO ENTROPIA
    entropy = calculate_entropy(data)
    info["entropy"] = entropy

    if entropy > 6.5:  # Soglia ragionevole
        info["packed_indicators"].append(f"Entropia alta: {entropy:.2f}")
        info["confidence"] += 0.4

    # 2. CONTROLLO SPECIFICO PE
    if ftype == "PE" and PEFILE_AVAILABLE:
        try:
            pe = pefile.PE(data=data)
            # NOTA: ".rsrc" rimossa dall'elenco — non è una firma di packer,
            # è una sezione STANDARD di risorse (icone, manifest, stringhe)
            # presente in quasi ogni PE legittimo. Includerla generava
            # falsi positivi sistematici (aggravati dal fatto che, essendo
            # confrontata in minuscolo contro sec_name reso maiuscolo da
            # .upper() poche righe sotto, il confronto non scattava mai:
            # bug che nascondeva l'errore concettuale, non lo risolveva).
            known_packers = [
                b"UPX", b"ASPACK", b"PECOMPACT", b"THEMIDA",
                b"PERESIZE", b"UPX0", b"UPX1"
            ]

            for section in pe.sections:
                sec_name = section.Name.rstrip(b"\x00").upper()

                # Verifica sezioni sospette
                for packer_sig in known_packers:
                    if packer_sig in sec_name:
                        info["packed_indicators"].append(
                            f"Sezione packer rilevata: {sec_name.decode('utf-8', errors='ignore')}"
                        )
                        info["confidence"] += 0.3

                # Sezioni con entropia anormalmente alta
                sec_data = section.get_data()
                if sec_data:
                    sec_entropy = calculate_entropy(sec_data)
                    if sec_entropy > 7.0:
                        info["packed_indicators"].append(
                            f"Sezione {sec_name.decode('utf-8', errors='ignore')} con entropia: {sec_entropy:.2f}"
                        )
                        info["confidence"] += 0.2

        except Exception as e:
            print(f"[!] Errore nell'analisi PE: {e}")

    # 3. CONTROLLO SPECIFICO ELF
    elif ftype == "ELF" and ELFTOOLS_AVAILABLE:
        try:
            # Riusa i byte già letti in `data` invece di riaprire il file
            # da disco una seconda volta: stesso identico contenuto,
            # una I/O in meno.
            elf = ELFFile(io.BytesIO(data))
            for section in elf.iter_sections():
                sec_name = section.name.upper()

                if "UPX" in sec_name or ".PACKED" in sec_name:
                    info["packed_indicators"].append(
                        f"Sezione packer rilevata: {section.name}"
                    )
                    info["confidence"] += 0.3

                # Analizza entropia della sezione
                sec_data = section.data()
                if sec_data:
                    sec_entropy = calculate_entropy(sec_data)
                    if sec_entropy > 7.0:
                        info["packed_indicators"].append(
                            f"Sezione {section.name} con entropia: {sec_entropy:.2f}"
                        )
                        info["confidence"] += 0.2

        except Exception as e:
            print(f"[!] Errore nell'analisi ELF: {e}")

    # Decisione finale: packed se confidence > 0.5
    is_packed = info["confidence"] > 0.5

    return is_packed, info

# ============================================================================
# UNPACKING
# ============================================================================

def unpack_with_unipacker(input_path: str, output_path: str) -> bool:
    """
    Esegue l'unpacking usando Unipacker da CLI.

    Unipacker deve essere installato: pip install unipacker

    Args:
        input_path: Percorso del file packed
        output_path: Percorso di output del file unpacked

    Returns:
        bool: True se unpacking ha successo
    """
    try:
        print(f"[*] Avvio Unipacker su: {input_path}")

        # Crea directory di output se non esiste
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # Esegui Unipacker
        result = subprocess.run(
            ["python", "-m", "unipacker", input_path],
            capture_output=True,
            timeout=120,  # Timeout 2 minuti
            text=True
        )

        if result.returncode == 0:
            print("[+] Unpacking completato con successo")

            # Unipacker tipicamente dumpa in una directory con nome del file
            # Cerca il risultato
            expected_output = f"{input_path}.unpacked"
            if os.path.exists(expected_output):
                os.rename(expected_output, output_path)
                print(f"[+] File salvato in: {output_path}")
                return True
            else:
                print("[!] Output di Unipacker trovato ma non nel percorso atteso")
                print(f"[*] Stdout: {result.stdout}")
                return False
        else:
            print(f"[-] Unipacker errore (exit code {result.returncode})")
            print(f"[*] Stderr: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print("[-] Timeout durante unpacking (>120s). Il file potrebbe essere complesso.")
        return False
    except FileNotFoundError:
        print("[-] Unipacker non trovato!")
        print("[*] Installa: pip install unipacker")
        return False
    except Exception as e:
        print(f"[-] Errore durante unpacking: {e}")
        return False


def unpack_with_upx(input_path: str, output_path: str) -> bool:
    """
    Fallback: Tenta unpacking con UPX (se file era compresso con UPX).
    UPX deve essere installato nel sistema.

    Args:
        input_path: Percorso del file packed
        output_path: Percorso di output

    Returns:
        bool: True se unpacking ha successo
    """
    try:
        print(f"[*] Tentativo unpacking con UPX: {input_path}")

        result = subprocess.run(
            ["upx", "-d", input_path, "-o", output_path],
            capture_output=True,
            timeout=60,
            text=True
        )

        if result.returncode == 0:
            print(f"[+] UPX unpacking completato: {output_path}")
            return True
        else:
            print(f"[-] UPX fallito (exit code {result.returncode})")
            return False

    except FileNotFoundError:
        print("[-] UPX non installato. Installa: apt-get install upx (Linux) o scaricare da upx.sourceforge.net")
        return False
    except subprocess.TimeoutExpired:
        print("[-] Timeout UPX (>60s)")
        return False
    except Exception as e:
        print(f"[-] Errore UPX: {e}")
        return False


# ============================================================================
# PIPELINE PRINCIPALE
# ============================================================================

def smart_unpack_pipeline(input_path: str, output_path: str) -> bool:
    """
    Pipeline intelligente di unpacking:
    1. Analizza il file
    2. Se packed, tenta unpacking con Unipacker
    3. Se Unipacker fallisce e è UPX, tenta UPX
    4. Altrimenti il file viene preso da binaries così com'è

    Args:
        input_path: File da analizzare
        output_path: Percorso output

    Returns:
        bool: True se operazione completata
    """
    print("\n" + "=" * 70)
    print(f"[*] Analisi preliminare di: {input_path}")
    print("=" * 70)

    # Verifica che il file esista
    if not os.path.exists(input_path):
        print(f"[-] File non trovato: {input_path}")
        return False

    # Analizza il file
    is_packed, info = is_likely_packed(input_path)

    print(f"[*] Tipo file: {info['type']}")
    print(f"[*] Entropia: {info['entropy']:.2f}")
    print(f"[*] Confidence packed: {info['confidence'] * 100:.0f}%")

    if info["packed_indicators"]:
        print("[!] Indicatori di packing rilevati:")
        for indicator in info["packed_indicators"]:
            print(f"    - {indicator}")

    # Decisione unpacking
    if is_packed:
        print("\n[!] Il file risulta PACKED. Avvio unpacking...")

        # Tenta Unipacker
        if unpack_with_unipacker(input_path, output_path):
            print(f"[+] SUCCESS: File scompattato salvato in: {output_path}")
            return True

        # Fallback: Tenta UPX se sembra essere un file UPX
        print("[*] Unipacker fallito. Tentativo con UPX...")
        if unpack_with_upx(input_path, output_path):
            print(f"[+] SUCCESS: File scompattato con UPX: {output_path}")
            return True

        # Fallback finale: copia il file originale
        print("[!] Unpacking fallito. Copia del file originale...")
        try:
            with open(input_path, "rb") as fin:
                with open(output_path, "wb") as fout:
                    fout.write(fin.read())
            print(f"[=] File copiato in: {output_path}")
            return True
        except Exception as e:
            print(f"[-] Errore nella copia: {e}")
            return False

    else:
        print("[=] Il file NON sembra packed. Copia diretta...")
        return False

