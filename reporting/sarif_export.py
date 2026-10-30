"""
sarif_export.py
--------------------------------------------------------------------
Esportazione in formato SARIF 2.1.0 (Static Analysis Results
Interchange Format), il formato standard che GitHub Code Scanning e
altri strumenti CI/CD sanno importare nativamente (punto 2 dello
spec: "SARIF: Export for integration with CI/CD tools like GitHub
Code Scanning").

Schema minimale ma valido: un solo "run", un "tool.driver" per
motore effettivamente presente nei finding (cosi' GitHub mostra
correttamente da quale engine viene ciascun risultato), un "result"
per finding con location (file + riga, quando disponibile) e livello
di severita' mappato sui tre livelli SARIF standard (error/warning/note).
--------------------------------------------------------------------
"""

from __future__ import annotations

import json
from pathlib import Path

_SARIF_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "error": "error",
    "medium": "warning",
    "warning": "warning",
    "low": "note",
}


def _sarif_level(severity: str | None) -> str:
    if not severity:
        return "warning"
    return _SARIF_SEVERITY_MAP.get(severity.strip().lower(), "warning")


def _rule_id(finding: dict) -> str:
    return finding.get("rule") or finding.get("cwe") or "unknown-rule"


def build_sarif(findings: list[dict], binary_name: str) -> dict:
    """
    Costruisce il documento SARIF come dict Python (pronto per
    json.dump). Un "driver" per ogni engine presente nei finding.
    """
    engines = sorted({f.get("engine", "yara") for f in findings}) or ["yara"]

    runs = []
    for engine in engines:
        engine_findings = [f for f in findings if f.get("engine", "yara") == engine]

        rule_ids_seen = {}
        for f in engine_findings:
            rid = _rule_id(f)
            rule_ids_seen.setdefault(rid, f.get("description", rid))

        rules = [
            {"id": rid, "shortDescription": {"text": desc}}
            for rid, desc in rule_ids_seen.items()
        ]

        results = []
        for f in engine_findings:
            region = {}
            if f.get("line"):
                region["startLine"] = int(f["line"])
            if f.get("matched_line"):
                region["snippet"] = {"text": f["matched_line"]}

            results.append({
                "ruleId": _rule_id(f),
                "level": _sarif_level(f.get("severity")),
                "message": {"text": f.get("description", f.get("rule", "finding"))},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", binary_name)},
                        "region": region,
                    },
                    "logicalLocations": [{"fullyQualifiedName": f.get("function", "")}],
                }],
                "properties": {
                    "cwe": f.get("cwe", ""),
                    "confidence": f.get("confidence", ""),
                    "tainted": f.get("tainted", False),
                },
            })

        runs.append({
            "tool": {
                "driver": {
                    "name": engine,
                    "informationUri": "",
                    "rules": rules,
                }
            },
            "results": results,
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def write_sarif(findings: list[dict], binary_name: str, output_path: str | Path) -> None:
    sarif_doc = build_sarif(findings, binary_name)
    Path(output_path).write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False), encoding="utf-8")
    