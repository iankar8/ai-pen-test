#!/usr/bin/env python3
"""
codeql_runner.py — build a CodeQL database and run the default security-extended
suite, then normalize SARIF findings.

Languages / build modes (per the runbook's fair-config contract):
  * Python (SecurityEval): `--build-mode=none` — no compilation needed.
  * Java (OWASP BenchmarkJava, a Maven project): autobuild — CodeQL runs `mvn`.
    Compiled-language DB build is the documented friction point; if it fails we
    say so, we do NOT silently drop it.

Query suite: `<lang>-security-extended.qls` (the standard extended security pack).

GUARD: if the `codeql` CLI is not on PATH, print a clear install pointer and exit
2 WITHOUT crashing the rest of the harness (the caller can continue with the
other tools). We never fabricate CodeQL numbers when the CLI is absent.

CWE mapping: SARIF rules carry tags like `external/cwe/cwe-089`; we read
`runs[].tool.driver.rules[].properties.tags`, map ruleId -> CWE, and attach it to
each result.

Usage:
    python benchmark/runners/codeql_runner.py \
        --index benchmark/datasets/securityeval_index.json \
        --target-root benchmark/datasets/SecurityEval \
        --language python --build-mode none \
        --out benchmark/results/codeql_securityeval.findings.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from normalize import (  # noqa: E402
    build_envelope, load_index, make_finding, parse_cwe, rel_path, write_envelope,
)

INSTALL_HINT = (
    "CodeQL CLI not found — install it and re-run.\n"
    "  1. Download the CLI bundle: "
    "https://github.com/github/codeql-action/releases (or `gh release`),\n"
    "     or `brew install codeql` on macOS.\n"
    "  2. Ensure `codeql` is on PATH (`codeql version` should print).\n"
    "See benchmark/README.md > CodeQL for the full setup + exact commands."
)


def _codeql_bin() -> Optional[str]:
    return shutil.which("codeql")


def _codeql_version(bin_path: str) -> str:
    try:
        out = subprocess.run([bin_path, "version", "--format=terse"],
                             capture_output=True, text=True, timeout=60)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def build_db(bin_path: str, source_root: str, language: str,
             build_mode: str, db_dir: str) -> None:
    cmd = [bin_path, "database", "create", db_dir,
           f"--language={language}", f"--source-root={source_root}", "--overwrite"]
    if build_mode:
        cmd.append(f"--build-mode={build_mode}")
    print(f"[codeql] {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"CodeQL database build failed (exit {proc.returncode}) for "
            f"language={language} build-mode={build_mode}.\n"
            f"stderr tail:\n{proc.stderr[-3000:]}")


def analyze_db(bin_path: str, db_dir: str, language: str, sarif_out: str) -> str:
    suite = f"{language}-security-extended.qls"
    cmd = [bin_path, "database", "analyze", db_dir, suite,
           "--format=sarif-latest", f"--output={sarif_out}", "--rerun"]
    print(f"[codeql] {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"CodeQL analyze failed (exit {proc.returncode}).\n"
            f"stderr tail:\n{proc.stderr[-3000:]}")
    return suite


def _rule_cwe_map(run: Dict[str, Any]) -> Dict[str, Optional[int]]:
    """Map ruleId -> CWE int from the SARIF driver rules' tags."""
    mapping: Dict[str, Optional[int]] = {}
    driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
    for rule in driver.get("rules", []) or []:
        rid = rule.get("id")
        tags = ((rule.get("properties", {}) or {}).get("tags", []) or [])
        cwe = None
        for t in tags:
            if "cwe" in str(t).lower():
                cwe = parse_cwe(t)
                if cwe is not None:
                    break
        if rid is not None:
            mapping[rid] = cwe
    return mapping


def parse_sarif(sarif_path: str, target_root: Optional[str]) -> List[Dict[str, Any]]:
    data = json.loads(Path(sarif_path).read_text())
    findings: List[Dict[str, Any]] = []
    for run in data.get("runs", []):
        rule_cwe = _rule_cwe_map(run)
        for res in run.get("results", []):
            rid = res.get("ruleId")
            cwe = rule_cwe.get(rid)
            severity = ((res.get("properties", {}) or {}).get("severity")
                        or res.get("level", "warning"))
            for loc in res.get("locations", []) or []:
                phys = (loc.get("physicalLocation", {}) or {})
                uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = (phys.get("region", {}) or {}).get("startLine")
                findings.append(make_finding(
                    rel_path(uri, target_root), line, cwe, str(severity), rule_id=rid))
    return findings


def main() -> None:
    ap = argparse.ArgumentParser(description="Run CodeQL security-extended and normalize SARIF findings.")
    ap.add_argument("--index", help="dataset ground-truth index JSON (for target-root relativization)")
    ap.add_argument("--target-root", required=True,
                    help="source root to build the CodeQL DB from (the dataset repo dir)")
    ap.add_argument("--language", required=True, choices=["python", "java", "javascript"],
                    help="CodeQL language")
    ap.add_argument("--build-mode", default="none",
                    help="build mode: 'none' for Python/JS, '' (autobuild) for Java")
    ap.add_argument("--out", default=None, help="output findings envelope path")
    ap.add_argument("--db-dir", default=None, help="reuse/keep the CodeQL DB here (default: temp)")
    ap.add_argument("--sarif", default=None, help="write raw SARIF here (default: temp)")
    args = ap.parse_args()

    bin_path = _codeql_bin()
    if not bin_path:
        # GUARD: clear message, non-fatal to the wider harness.
        print(f"[codeql] {INSTALL_HINT}", file=sys.stderr)
        sys.exit(2)

    version = _codeql_version(bin_path)
    source_root = str(Path(args.target_root).resolve())
    build_mode = None if args.build_mode in ("", "autobuild") else args.build_mode

    tmp = tempfile.mkdtemp(prefix="codeql_bench_")
    db_dir = args.db_dir or str(Path(tmp) / "db")
    sarif_out = args.sarif or str(Path(tmp) / "results.sarif")

    print(f"[codeql] version {version}; language={args.language} "
          f"build-mode={build_mode or 'autobuild'} source={source_root}")

    build_db(bin_path, source_root, args.language, build_mode, db_dir)
    suite = analyze_db(bin_path, db_dir, args.language, sarif_out)
    findings = parse_sarif(sarif_out, source_root)

    envelope = build_envelope(
        tool="codeql",
        findings=findings,
        target_root=source_root,
        tool_version=version,
        config=f"codeql database analyze <{args.language}-security-extended.qls> "
               f"(build-mode={build_mode or 'autobuild'})",
        edition="OSS-suite",
        invocation=f"codeql database create --language={args.language} "
                   f"--build-mode={build_mode or 'autobuild'}; analyze {suite}",
        dry_run=False,
    )

    out = args.out or str(Path(__file__).resolve().parents[1] / "results" / "codeql.findings.json")
    write_envelope(envelope, out)
    print(f"[codeql] {len(findings)} findings -> {out}")
    print(f"[codeql] raw SARIF: {sarif_out}")


if __name__ == "__main__":
    main()
