#!/usr/bin/env python3
"""
semgrep_runner.py — run Semgrep over dataset files and emit normalized findings.

Invocation of record:  semgrep --config auto --json <target...>

`--config auto` pulls the Registry ("Community"/Open-Source) ruleset for the
detected languages. This is the FREE Community Edition (CE) — no Semgrep Pro
engine, no cross-file/interprocedural analysis. We record `edition: "CE"` and say
so in `config`, because comparing a cross-file LLM tool to Semgrep CE without that
disclosure would itself be a strawman (per the runbook's fairness contract).

CWE mapping: Semgrep results carry `extra.metadata.cwe` (e.g. ["CWE-89: ..."]);
we parse the integer out. Findings with no CWE metadata keep cwe=null (they still
appear, but can only match a ground-truth CWE if one is present).

No API key required.

Usage:
    python benchmark/runners/semgrep_runner.py \
        --index benchmark/datasets/securityeval_index.json \
        --target-root benchmark/datasets/SecurityEval \
        --out benchmark/results/semgrep_securityeval.findings.json
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
    build_envelope, load_index, make_finding, rel_path, write_envelope,
)


def _semgrep_bin() -> Optional[str]:
    # prefer the venv's semgrep, then PATH
    venv_bin = Path(sys.executable).parent / "semgrep"
    if venv_bin.exists():
        return str(venv_bin)
    return shutil.which("semgrep")


def _semgrep_version(bin_path: str) -> str:
    try:
        out = subprocess.run([bin_path, "--version"], capture_output=True, text=True, timeout=30)
        return out.stdout.strip().splitlines()[0] if out.stdout else "unknown"
    except Exception:
        return "unknown"


def _target_paths(index_path: Optional[str], target_root: Optional[str],
                  single_target: Optional[str]) -> List[str]:
    if single_target:
        return [str(Path(single_target).resolve())]
    entries = load_index(index_path)
    root = Path(target_root) if target_root else Path(".")
    return [str((root / e["file"]).resolve()) for e in entries]


def parse_semgrep_json(data: Dict[str, Any], target_root: Optional[str]) -> List[Dict[str, Any]]:
    """Map Semgrep JSON `results[]` to normalized findings."""
    findings: List[Dict[str, Any]] = []
    for r in data.get("results", []):
        meta = (r.get("extra", {}) or {}).get("metadata", {}) or {}
        cwe = meta.get("cwe")  # usually a list like ["CWE-89: ..."]
        severity = (r.get("extra", {}) or {}).get("severity", "UNKNOWN")
        line = (r.get("start", {}) or {}).get("line")
        findings.append(make_finding(
            rel_path(r.get("path", ""), target_root),
            line,
            cwe,
            severity,
            rule_id=r.get("check_id"),
        ))
    return findings


def run_semgrep(targets: List[str], bin_path: str, config: str,
                target_root: Optional[str]) -> (List[Dict[str, Any]], str):
    """Run semgrep once over all targets; return (findings, invocation string).

    Targets are written to a temp file and passed via stdin path list is not a
    semgrep feature, so we pass targets on the CLI in batches if needed. For our
    dataset sizes (<= a few hundred files) a single invocation is fine.
    """
    cmd = [bin_path, "--config", config, "--json", "--quiet",
           "--disable-version-check"]
    # `--config auto` fetches the Registry ruleset and REQUIRES metrics enabled
    # (semgrep refuses auto with metrics off). For any pinned ruleset we turn
    # metrics off. This is documented in the envelope's `config` string.
    if config != "auto":
        cmd += ["--metrics", "off"]
    cmd += targets
    metrics_note = "metrics=on (required by auto)" if config == "auto" else "metrics=off"
    invocation = f"{Path(bin_path).name} --config {config} --json ({metrics_note}) <{len(targets)} targets>"
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # semgrep exits non-zero when it finds issues OR on error; distinguish via stdout JSON.
    if not proc.stdout.strip():
        raise RuntimeError(
            f"semgrep produced no JSON output (exit {proc.returncode}).\n"
            f"stderr:\n{proc.stderr[:2000]}")
    data = json.loads(proc.stdout)
    if data.get("errors"):
        # keep going but surface errors in the envelope via stderr print
        print(f"[semgrep] {len(data['errors'])} rule/parse errors reported "
              f"(non-fatal); first: {json.dumps(data['errors'][0])[:300]}",
              file=sys.stderr)
    return parse_semgrep_json(data, target_root), invocation


def main() -> None:
    ap = argparse.ArgumentParser(description="Run Semgrep (CE) and normalize findings.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--index", help="dataset ground-truth index JSON")
    src.add_argument("--target", help="scan a single file or directory")
    ap.add_argument("--target-root", help="root the index `file` paths are relative to")
    ap.add_argument("--config", default="auto", help="semgrep --config value (default: auto)")
    ap.add_argument("--out", default=None, help="output findings envelope path")
    args = ap.parse_args()

    bin_path = _semgrep_bin()
    if not bin_path:
        print("[semgrep] Semgrep CLI not found. Install with: "
              "/Users/iankar/ai-pen-test/.venv/bin/pip install semgrep — see benchmark/README.md",
              file=sys.stderr)
        sys.exit(2)

    target_root = args.target_root
    if args.target and not target_root:
        p = Path(args.target).resolve()
        target_root = str(p if p.is_dir() else p.parent)

    targets = _target_paths(args.index, target_root, args.target)
    version = _semgrep_version(bin_path)
    print(f"[semgrep] version {version}; scanning {len(targets)} target(s) with --config {args.config}")

    findings, invocation = run_semgrep(targets, bin_path, args.config, target_root)

    envelope = build_envelope(
        tool="semgrep",
        findings=findings,
        target_root=target_root or ".",
        tool_version=version,
        config=f"semgrep --config {args.config} (Community Edition / CE; no Pro engine, no cross-file)",
        edition="CE",
        invocation=invocation,
        dry_run=False,
    )

    out = args.out or str(Path(__file__).resolve().parents[1] / "results" / "semgrep.findings.json")
    write_envelope(envelope, out)
    print(f"[semgrep] {len(findings)} findings -> {out}")


if __name__ == "__main__":
    main()
