# BinScan

**A modular pipeline for vulnerability discovery in binaries without source code.**

BinScan takes compiled ELF binaries (no source code, no debug info required), decompiles them, rebuilds their call graph, scans the pseudocode with three independent static analysis engines, generates targeted fuzzing seeds from the findings and produces an HTML/SARIF report.

It was developed for my MSc thesis in Computer Science – Cybersecurity at the University of Salerno (2026):
*"Reverse Engineering Assisted Vulnerability Discovery: a Modular Pipeline for the Analysis of Binaries without Source Code"*.

> Status: research prototype. The code comments and the per-module READMEs are written in Italian.

---

## Pipeline

```
 binary (ELF)
     │
     ▼
 1. Decompilation ──────── Ghidra headless (+ unpacking)          → pseudocode C + symbols
     │
     ▼
 2. Call graph / CFG ───── angr                                   → callgraph (GraphML)
     │
     ▼
 3. Vulnerability scan ─── YARA + taint · Semgrep · cwe_checker   → findings (CWE, line)
     │
     ▼
 4. Fuzzing ────────────── seed generator → AFL++ (QEMU mode)     → crashes → GDB triage
     │
     ▼
 5. Reporting ──────────── Jinja2 HTML + SARIF 2.1.0 + accuracy vs ground truth
```

An optional **LLM review** module (`llm_reviewer/`) gives a second opinion on the decompiled functions. It is kept separate from the three deterministic engines on purpose, so its probabilistic output never mixes with their results.

## Repository layout

| Path | Component |
|---|---|
| `pipe.py`, `main.py` | Orchestrator: runs every phase on each binary in `bins/`, one output folder per binary in `risultati/` |
| `decompiler/` | Ghidra headless decompilation (`DecompScript.java`) and unpacking |
| `angr_cfglib.py`, `relabel_graphs.py`, `visualize_graph.py` | CFG / call graph extraction and export |
| `vuln_scanner/` | Three scanning engines: YARA rules + numeric checks + taint analysis, Semgrep rules, cwe_checker (Docker) |
| `fuzz_seed_generator/` | Builds a seed corpus from buffer sizes, findings and call-graph reachability |
| `fuzzing_runner/`, `crash_analyzer/` | AFL++ campaigns in Docker (QEMU mode) and GDB crash triage |
| `reporting/` | HTML/SARIF reports, accuracy (TP/FP/FN by CWE family), Juliet ground-truth importer, aggregate report |
| `llm_reviewer/` | Optional LLM review (local Ollama model) |
| `claude_api_scanner*.py`, `generate_seeds_with_claude*.py` | Thesis experiments with the Claude API (detection and seed generation) |
| other `*.py` in the root | Scripts used for the thesis experiments (re-runs, ablations, comparisons) |
| `bins/vulnerable_read_overflow` | Small test binary with a real stack overflow |

## Results (from the thesis)

Evaluated on **142 binaries** from the NIST Juliet Test Suite (CWE-121, stack-based buffer overflow), **146 expected weaknesses**, compiled as ELF 64-bit with GCC:

- **114 / 146 weaknesses detected (78%)** in the right function with a CWE of the overflow family
- **100 / 142 binaries (70%)** flagged on the exact line of the defect
- **2 findings** on non-vulnerable functions after filtering library stubs
- On a real case, **CVE-2021-20294 in GNU readelf**, the vulnerable function is flagged by the scanning engine (among many other findings, as expected on a large real program)

The thesis also compares the pipeline with LLMs (Claude Haiku 4.5 and VulnLLM-R) on the same binaries, with and without function names, and shows that the hardest cases are the same for every approach: the limit is the information lost in the decompiled pseudocode.

## Requirements

- Python 3.9+
- [Ghidra](https://ghidra-sre.org/) 12.x (with a JDK) for headless decompilation
- Docker, for `cwe_checker` and AFL++ (`ghcr.io/fkie-cad/cwe_checker:stable`, `aflplusplus/aflplusplus`)
- Optional: [Ollama](https://ollama.com) for `llm_reviewer/`, an Anthropic API key for the Claude experiments

```bash
pip install -r requirements.txt
docker pull ghcr.io/fkie-cad/cwe_checker:stable
docker pull aflplusplus/aflplusplus
```

Set the path to Ghidra's headless analyzer:

```bash
# Windows (PowerShell)
$env:GHIDRA_HEADLESS = "C:\path\to\ghidra\support\analyzeHeadless.bat"
# Linux / macOS
export GHIDRA_HEADLESS=/path/to/ghidra/support/analyzeHeadless
```

For the Claude experiments, set `ANTHROPIC_API_KEY` in your environment. No key is stored in this repository.

## Usage

```bash
python pipe.py --list                       # list binaries in bins/
python pipe.py                              # run the pipeline on every binary in bins/
python pipe.py --only vulnerable_read_overflow
```

Results go to `risultati/<binary>/` (decompiled code, CFG, findings, `reporting/report.html` and `report.sarif`).

Fuzzing and LLM review are run separately (see `fuzzing_runner/README.md` and `llm_reviewer/README.md`).

To evaluate on Juliet, download the [Juliet Test Suite for C/C++](https://samate.nist.gov/SARD/test-suites) and use `copy_juliet_selection.py` and `reporting/juliet_ground_truth_importer.py` to build `bins/`, `sources/` and the ground truth. The Juliet binaries and the thesis results are not included in this repository.

## Author

**Oleg Harbar** – MSc in Computer Science (Cybersecurity), University of Salerno
Thesis supervisor: Prof. Arcangelo Castiglione
[LinkedIn](https://www.linkedin.com/in/oleg-harbar/)
