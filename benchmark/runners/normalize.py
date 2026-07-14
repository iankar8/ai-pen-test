#!/usr/bin/env python3
"""
normalize.py — shared normalized-findings schema for every benchmark runner.

Every runner (ai-pen-test, Semgrep, CodeQL) emits the SAME on-disk shape so the
scorer never has to know which tool produced a file. One schema, one scorer.

Normalized finding (per detection):
    {
        "file": "<path relative to target_root, POSIX>",
        "line": <int|null>,
        "cwe":  <int|null>,
        "severity": "<str>",
        "rule_id": "<str, optional>"
    }

Runner output envelope (what a runner writes / the scorer reads):
    {
        "tool": "semgrep",
        "tool_version": "1.169.0",
        "config": "semgrep --config auto",
        "edition": "CE",
        "target_root": "/abs/path/scanned",
        "invocation": "<exact command line, when applicable>",
        "timestamp": "<iso8601>",
        "dry_run": false,
        "findings": [ ...normalized findings... ]
    }

Honesty note: the envelope records the EXACT invocation and whether the run was a
dry-run/mock. A mock run is always flagged `dry_run: true` so no consumer can
mistake stubbed findings for a real engine result.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_CWE_RE = re.compile(r"(\d+)")


def parse_cwe(value: Any) -> Optional[int]:
    """Extract a CWE integer from any of: 89, "89", "CWE-89", "CWE-089: SQLi",
    "external/cwe/cwe-089". Returns None if no integer is present.

    Only the FIRST integer run is used, which is the CWE number in every format
    we handle. This never guesses a CWE — no digits in, None out.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple)):
        for item in value:
            got = parse_cwe(item)
            if got is not None:
                return got
        return None
    m = _CWE_RE.search(str(value))
    return int(m.group(1)) if m else None


def rel_path(path: str, target_root: Optional[str]) -> str:
    """Return `path` relative to `target_root` (POSIX), or the cleaned path if it
    is not under the root. Used so tool findings key the same way as ground-truth
    `file` fields (which are relative to the dataset root)."""
    p = Path(path)
    if target_root:
        root = Path(target_root)
        try:
            return p.resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            pass
    return p.as_posix()


def make_finding(
    file: str,
    line: Optional[int],
    cwe: Any,
    severity: str = "UNKNOWN",
    rule_id: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    """Build one normalized finding dict."""
    finding: Dict[str, Any] = {
        "file": Path(file).as_posix(),
        "line": int(line) if line is not None else None,
        "cwe": parse_cwe(cwe),
        "severity": (severity or "UNKNOWN").upper(),
    }
    if rule_id is not None:
        finding["rule_id"] = rule_id
    if extra:
        finding.update(extra)
    return finding


def build_envelope(
    tool: str,
    findings: List[Dict[str, Any]],
    target_root: str,
    tool_version: str = "unknown",
    config: str = "",
    edition: str = "",
    invocation: str = "",
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Assemble the full runner-output envelope."""
    return {
        "tool": tool,
        "tool_version": tool_version,
        "config": config,
        "edition": edition,
        "target_root": str(Path(target_root).resolve()),
        "invocation": invocation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "finding_count": len(findings),
        "findings": findings,
    }


def write_envelope(envelope: Dict[str, Any], out_path: str) -> None:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(envelope, indent=2))


def load_index(index_path: str) -> List[Dict[str, Any]]:
    """Load a dataset ground-truth index (list of {id, file, cwe, is_vulnerable, ...})."""
    return json.loads(Path(index_path).read_text())
