import re
import os
import json
import argparse

FUNC_SIGNATURE_RE = re.compile(
    r'^[A-Za-z_][A-Za-z0-9_ \*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*\)\s*$',
    re.MULTILINE
)


def find_function_blocks(source_text):
    functions = []  # Corretto: usa una lista
    lines = source_text.splitlines(keepends=True)

    i = 0
    while i < len(lines):
        line = lines[i]
        match = FUNC_SIGNATURE_RE.match(line.strip())

        if match:
            func_name = match.group(1)
            start_line = i
            j = i + 1

            # Salta righe vuote prima dell'apertura del blocco
            while j < len(lines) and lines[j].strip() == '':
                j += 1

            if j < len(lines) and lines[j].strip().startswith('{'):
                brace_count = 0
                k = j
                started = False

                while k < len(lines):
                    brace_count += lines[k].count('{')
                    brace_count -= lines[k].count('}')

                    if '{' in lines[k]:
                        started = True

                    if started and brace_count == 0:
                        break

                    k += 1

                func_code = ''.join(lines[start_line:k + 1])
                functions.append({
                    "name": func_name,
                    "code": func_code
                })

                # Salta oltre il blocco della funzione trovata
                i = k + 1
                continue

        i += 1

    return functions  # Corretto: fuori dal ciclo while


def split_file(decompiled_path, output_dir):
    with open(decompiled_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    functions = find_function_blocks(content)

    os.makedirs(output_dir, exist_ok=True)
    manifest = []

    for idx, func in enumerate(functions):
        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', func["name"])
        filename = f"{idx:03d}_{safe_name}.c"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as out:
            out.write(func['code'])

        manifest.append({
            "index": idx,
            "ghidra_name": func['name'],
            "file": filename
        })

    # Scrittura del manifest e return SPOSTATI FUORI dal ciclo for
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, 'w', encoding='utf-8') as mf:
        json.dump(manifest, mf, indent=2)

    return len(functions)


if __name__ == "__main__":
    input_c_file = r"risultati/<binary_name>/decompiled_files/<binary_name>_decompiled.c"
    output_dir = "prepare_dataset/file"
    n = split_file(input_c_file, output_dir)
    print(f"Trovate e salvate {n} funzioni in {output_dir}")