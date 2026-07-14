#!/usr/bin/env python3
"""
ai_pen_test_runner.py — run the SHIPPED ai-pen-test engine over dataset files and
emit normalized findings.

The shipped engine is handlers.sast_analyzer.SASTAnalyzer (analyze_codebase /
_analyze_file). Real mode calls it; the LLM step needs OPENROUTER_API_KEY (or
ANTHROPIC_API_KEY for the direct-Anthropic path).

MODES
-----
real     : instantiate SASTAnalyzer and call the engine per file. Requires a key.
dry-run  : return a DETERMINISTIC MOCK finding set from a small stubbed map — NO
           network, NO spend, NO LLM. Flagged `dry_run: true` in the envelope so
           nobody can mistake it for a real result. Used to verify the harness
           plumbing (runner -> normalize -> scorer) at zero cost.

`--dry-run` forces mock mode. If no API key is present, the runner AUTO-falls back
to mock mode (and says so) rather than fabricating a real run.

Usage:
    python benchmark/runners/ai_pen_test_runner.py \
        --index benchmark/datasets/securityeval_index.json \
        --target-root benchmark/datasets/SecurityEval \
        --out benchmark/results/ai_pen_test_securityeval.findings.json \
        --dry-run

    python benchmark/runners/ai_pen_test_runner.py --file path/to/one.py --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# make `handlers` (repo root) and `runners` importable
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from normalize import (  # noqa: E402
    build_envelope, load_index, make_finding, rel_path, write_envelope,
)

# A small, explicit stubbed map for deterministic mock findings. Keyed by file
# basename for a couple of real dataset files; everything else uses the
# deterministic hash fallback below. These are FAKE placeholders — they exist
# only to prove findings flow end-to-end without spend.
STUB_FINDINGS: Dict[str, Dict[str, Any]] = {
    "author_1.py": {"cwe": 89, "line": 7, "severity": "HIGH"},
    "BenchmarkTest00001.java": {"cwe": 22, "line": 30, "severity": "MEDIUM"},
}

# CWE pool the deterministic fallback draws from (ai-pen-test's core coverage).
_MOCK_CWE_POOL = [89, 79, 78, 22, 327, 328, 502, 90, 643, 611]
_MOCK_SEV = ["CRITICAL", "HIGH", "MEDIUM"]


def _mock_findings_for_file(abs_path: str, target_root: Optional[str]) -> List[Dict[str, Any]]:
    """Deterministic, network-free mock finding(s) for one file.

    Deterministic: identical inputs -> identical outputs (md5 of the relative
    path drives the choice). Roughly 4 of every 5 files get a stub finding so the
    scorer sees a realistic mix of hits and misses; the rest get none.
    """
    rel = rel_path(abs_path, target_root)
    base = Path(abs_path).name

    if base in STUB_FINDINGS:
        s = STUB_FINDINGS[base]
        return [make_finding(rel, s["line"], s["cwe"], s["severity"],
                             rule_id="MOCK-STUB", mock=True)]

    h = int(hashlib.md5(rel.encode()).hexdigest(), 16)
    if h % 5 == 0:  # ~20% of files: engine stays silent
        return []
    cwe = _MOCK_CWE_POOL[h % len(_MOCK_CWE_POOL)]
    line = (h % 40) + 1
    sev = _MOCK_SEV[h % len(_MOCK_SEV)]
    return [make_finding(rel, line, cwe, sev, rule_id="MOCK-HASH", mock=True)]


def _collect_files(index_path: Optional[str], target_root: Optional[str],
                   single_file: Optional[str]) -> List[str]:
    if single_file:
        return [str(Path(single_file).resolve())]
    entries = load_index(index_path)
    root = Path(target_root) if target_root else Path(".")
    files = []
    for e in entries:
        p = (root / e["file"]).resolve()
        files.append(str(p))
    return files


def run_mock(files: List[str], target_root: Optional[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for f in files:
        findings.extend(_mock_findings_for_file(f, target_root))
    return findings


def run_real(files: List[str], target_root: Optional[str], model: str,
             api_key: Optional[str], backend: str = "openrouter") -> List[Dict[str, Any]]:
    """Call the SHIPPED engine per file. openrouter needs a key; codex needs the CLI."""
    from handlers.sast_analyzer import SASTAnalyzer

    analyzer = SASTAnalyzer(model=model, api_key=api_key,
                            use_openrouter=(backend == "openrouter"), backend=backend)
    findings: List[Dict[str, Any]] = []
    for f in files:
        engine_findings = analyzer._analyze_file(f, None)
        for ef in engine_findings:
            findings.append(make_finding(
                rel_path(ef.file, target_root),
                ef.line,
                ef.cwe,
                ef.severity,
                rule_id=ef.id,
            ))
    return findings


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the shipped ai-pen-test engine and normalize findings.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--index", help="dataset ground-truth index JSON")
    src.add_argument("--file", help="scan a single file")
    ap.add_argument("--target-root", help="root the index `file` paths are relative to")
    ap.add_argument("--out", default=None, help="output findings envelope path")
    ap.add_argument("--model", default="claude", help="engine model id (real mode)")
    ap.add_argument("--backend", default="openrouter", choices=["openrouter", "codex"],
                    help="openrouter (metered API key) or codex (bills to ChatGPT/Codex subscription)")
    ap.add_argument("--dry-run", action="store_true",
                    help="force deterministic MOCK mode (no network, no spend)")
    args = ap.parse_args()

    target_root = args.target_root
    if args.file and not target_root:
        target_root = str(Path(args.file).resolve().parent)

    files = _collect_files(args.index, target_root, args.file)

    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    # codex backend uses subscription auth (the CLI), not an API key.
    if args.backend == "codex":
        use_mock = args.dry_run
        no_backend_reason = "--dry-run"
    else:
        use_mock = args.dry_run or not api_key
        no_backend_reason = "--dry-run" if args.dry_run else "no OPENROUTER_API_KEY/ANTHROPIC_API_KEY in env"

    if use_mock:
        print(f"[ai-pen-test] MOCK mode ({no_backend_reason}): deterministic stub findings, "
              f"no network, no spend.")
        findings = run_mock(files, target_root)
        config = "MOCK (dry-run); real engine NOT invoked"
        invocation = f"ai_pen_test_runner.py --dry-run over {len(files)} files"
        dry = True
    else:
        print(f"[ai-pen-test] REAL mode (backend={args.backend}): invoking shipped SASTAnalyzer on {len(files)} files.")
        findings = run_real(files, target_root, args.model, api_key, args.backend)
        config = f"SASTAnalyzer(model={args.model}, backend={args.backend})"
        invocation = f"ai_pen_test_runner.py --model {args.model} --backend {args.backend} over {len(files)} files"
        dry = False

    envelope = build_envelope(
        tool="ai_pen_test",
        findings=findings,
        target_root=target_root or ".",
        tool_version="shipped-engine (handlers/sast_analyzer.py)",
        config=config,
        edition="LLM",
        invocation=invocation,
        dry_run=dry,
    )

    out = args.out or str(Path(__file__).resolve().parents[1] / "results" /
                          "ai_pen_test.findings.json")
    write_envelope(envelope, out)
    print(f"[ai-pen-test] {len(findings)} findings over {len(files)} files -> {out}")
    print(f"[ai-pen-test] dry_run={dry}")


if __name__ == "__main__":
    main()
