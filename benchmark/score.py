#!/usr/bin/env python3
"""
score.py — the credibility core.

Given a dataset ground-truth index and a tool's NORMALIZED findings, compute a
confusion matrix and precision / recall / F1 (plus TPR / FPR / Youden where a
true-negative population exists), reported PER CWE and OVERALL, at TWO match
granularities:

  1. file+CWE match  (headline; fair across tools with different line granularity)
  2. strict line-match (±`line_tolerance` lines; secondary)

Scoring model (case-level, matching the per-file corpora these datasets use):
each ground-truth entry is one file with one expected CWE and an is_vulnerable
label. An entry is "detected" if the tool produced >=1 finding in that file
whose CWE equals the entry's CWE (and, for line granularity on VULNERABLE
entries, within tolerance of the entry's labelled line).

    is_vulnerable=True,  detected  -> TP
    is_vulnerable=True,  missed    -> FN
    is_vulnerable=False, detected  -> FP  (false alarm on a safe file)
    is_vulnerable=False, missed    -> TN

HONESTY RULES baked in (never fabricate a metric):
  * If a bucket has NO non-vulnerable samples (neg == 0), precision / FPR /
    Youden / F1 are reported as null with a reason — a labelled-insecure-only
    corpus (e.g. SecurityEval) can measure RECALL ONLY. We do not emit a
    precision of 1.0 that is a structural artifact.
  * If a bucket has NO positive predictions (pred_pos == 0), precision is null
    (undefined), not 0.
  * If NO vulnerable ground-truth entry carries a line number, the entire
    line-match section is null with a reason ("ground truth has no line-level
    labels") rather than a fabricated 0.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Match granularities
GRAN_FILE_CWE = "file_cwe"
GRAN_LINE = "line"


# ---------------------------------------------------------------------------
# path matching
# ---------------------------------------------------------------------------
def _norm(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def _files_match(gt_file: str, finding_file: str) -> bool:
    """True if two paths refer to the same file. Exact normalized match, or one
    is a path-suffix of the other (guards differing root prefixes). Suffix match
    is on full path COMPONENTS so 'x/author_1.py' never matches 'y/author_1.py'
    unless the trailing components line up."""
    a, b = _norm(gt_file), _norm(finding_file)
    if a == b:
        return True
    ap, bp = a.split("/"), b.split("/")
    n = min(len(ap), len(bp))
    if n == 0:
        return False
    # require the shorter path to be a trailing slice of the longer, and to
    # include the filename plus (if available) at least one parent dir.
    depth = min(n, 2) if n >= 2 else 1
    return ap[-depth:] == bp[-depth:] and (a.endswith(b) or b.endswith(a))


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------
def _detected(entry: Dict[str, Any], findings: List[Dict[str, Any]],
              granularity: str, tol: int) -> bool:
    """Did the tool detect this ground-truth entry under the given granularity?"""
    gt_cwe = entry.get("cwe")
    gt_file = entry.get("file", "")
    is_vuln = bool(entry.get("is_vulnerable"))
    gt_line = entry.get("line")

    for f in findings:
        if f.get("cwe") != gt_cwe:
            continue
        if not _files_match(gt_file, f.get("file", "")):
            continue
        # file + CWE granularity: a CWE-matched finding in the file is enough.
        if granularity == GRAN_FILE_CWE:
            return True
        # line granularity:
        #   - non-vulnerable entries have no correct line; a CWE-matched finding
        #     in the file is a false alarm regardless of line -> treat as detected.
        #   - vulnerable entries require the finding line within tolerance.
        if not is_vuln:
            return True
        if gt_line is None:
            continue
        f_line = f.get("line")
        if f_line is not None and abs(int(f_line) - int(gt_line)) <= tol:
            return True
    return False


# ---------------------------------------------------------------------------
# metrics from a confusion matrix
# ---------------------------------------------------------------------------
def metrics_from_counts(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Any]:
    pos = tp + fn          # actual vulnerable
    neg = fp + tn          # actual safe (true-negative population)
    pred_pos = tp + fp     # things the tool flagged for this bucket

    notes: List[str] = []

    if neg == 0:
        # No safe samples => precision / FPR / Youden are undefined-for-purpose.
        precision = None
        fpr = None
        notes.append("no non-vulnerable samples in this bucket; "
                     "precision/FPR/Youden undefined — recall only")
    elif pred_pos == 0:
        precision = None
        fpr = fp / neg  # == 0.0 here, but explicit
        notes.append("no positive predictions in this bucket; precision undefined")
    else:
        precision = tp / pred_pos
        fpr = fp / neg

    recall = tp / pos if pos > 0 else None
    if pos == 0:
        notes.append("no vulnerable samples in this bucket; recall undefined")

    tpr = recall

    if precision is not None and recall is not None:
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
    else:
        f1 = None

    youden = (tpr - fpr) if (tpr is not None and fpr is not None) else None

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tpr": tpr,
        "fpr": fpr,
        "youden": youden,
        "notes": notes,
    }


def _confusion(entries: List[Dict[str, Any]], findings: List[Dict[str, Any]],
               granularity: str, tol: int) -> Dict[str, int]:
    tp = fp = fn = tn = 0
    for e in entries:
        detected = _detected(e, findings, granularity, tol)
        if e.get("is_vulnerable"):
            if detected:
                tp += 1
            else:
                fn += 1
        else:
            if detected:
                fp += 1
            else:
                tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _score_granularity(entries: List[Dict[str, Any]],
                       findings: List[Dict[str, Any]],
                       granularity: str, tol: int) -> Dict[str, Any]:
    overall_counts = _confusion(entries, findings, granularity, tol)
    overall = metrics_from_counts(**overall_counts)

    per_cwe: Dict[str, Any] = {}
    cwes = sorted({e.get("cwe") for e in entries if e.get("cwe") is not None})
    for cwe in cwes:
        bucket = [e for e in entries if e.get("cwe") == cwe]
        counts = _confusion(bucket, findings, granularity, tol)
        per_cwe[str(cwe)] = metrics_from_counts(**counts)

    return {"overall": overall, "per_cwe": per_cwe}


# ---------------------------------------------------------------------------
# public entrypoint
# ---------------------------------------------------------------------------
def compute_scores(ground_truth: List[Dict[str, Any]],
                   findings: List[Dict[str, Any]],
                   line_tolerance: int = 3,
                   tool: str = "unknown",
                   dataset: str = "unknown") -> Dict[str, Any]:
    """Score a tool's normalized findings against a ground-truth index.

    ground_truth: list of {file, cwe, is_vulnerable, line?, category?, id?}
    findings:     list of normalized findings {file, line, cwe, severity, ...}
    Returns the full results dict (JSON-serializable).
    """
    vulnerable = sum(1 for e in ground_truth if e.get("is_vulnerable"))
    non_vulnerable = len(ground_truth) - vulnerable
    vuln_entries_with_line = sum(
        1 for e in ground_truth
        if e.get("is_vulnerable") and e.get("line") is not None
    )

    result: Dict[str, Any] = {
        "tool": tool,
        "dataset": dataset,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "line_tolerance": line_tolerance,
        "match_criteria": {
            "file_cwe": "same file AND same CWE",
            "line": (f"same file AND same CWE AND finding line within "
                     f"+/-{line_tolerance} of the labelled line "
                     f"(vulnerable entries only)"),
        },
        "counts": {
            "ground_truth_entries": len(ground_truth),
            "vulnerable": vulnerable,
            "non_vulnerable": non_vulnerable,
            "tool_findings": len(findings),
            "vulnerable_entries_with_line_labels": vuln_entries_with_line,
        },
        "notes": [],
    }

    # file+CWE granularity (always computable)
    result["file_cwe_match"] = _score_granularity(
        ground_truth, findings, GRAN_FILE_CWE, line_tolerance)

    # line granularity — only if any vulnerable entry has a line label
    if vuln_entries_with_line == 0:
        result["line_match"] = None
        result["notes"].append(
            "line_match is null: no vulnerable ground-truth entry carries a "
            "line-level label, so strict line-match cannot be computed on this "
            "dataset (reported as PENDING, not fabricated).")
    else:
        result["line_match"] = _score_granularity(
            ground_truth, findings, GRAN_LINE, line_tolerance)

    if non_vulnerable == 0:
        result["notes"].append(
            "dataset has no non-vulnerable samples: this is a RECALL-ONLY "
            "measurement; precision / FPR / Youden are null by construction.")

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Score normalized SAST findings vs a dataset index.")
    ap.add_argument("--index", required=True, help="ground-truth index JSON (list of entries)")
    ap.add_argument("--findings", required=True, help="normalized findings envelope JSON")
    ap.add_argument("--tool", required=True, help="tool name (for output filename + record)")
    ap.add_argument("--dataset", required=True, help="dataset name (for output filename + record)")
    ap.add_argument("--tolerance", type=int, default=3, help="line-match tolerance (default 3)")
    ap.add_argument("--out", default=None,
                    help="output path (default results/<tool>_<dataset>.json)")
    args = ap.parse_args()

    ground_truth = json.loads(Path(args.index).read_text())

    findings_doc = json.loads(Path(args.findings).read_text())
    findings = findings_doc.get("findings", findings_doc) if isinstance(findings_doc, dict) else findings_doc

    result = compute_scores(
        ground_truth, findings,
        line_tolerance=args.tolerance, tool=args.tool, dataset=args.dataset)

    # carry through provenance from the findings envelope if present
    if isinstance(findings_doc, dict):
        result["findings_provenance"] = {
            k: findings_doc.get(k)
            for k in ("tool_version", "config", "edition", "invocation",
                      "target_root", "dry_run", "timestamp")
            if k in findings_doc
        }
        if findings_doc.get("dry_run"):
            result["notes"].insert(0,
                "SOURCE FINDINGS ARE A DRY-RUN/MOCK (dry_run=true): these scores "
                "validate the pipeline only and are NOT a real engine result.")

    out = args.out or str(Path(__file__).parent / "results" / f"{args.tool}_{args.dataset}.json")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(result, indent=2))
    print(f"[score] wrote {out}")
    ov = result["file_cwe_match"]["overall"]
    print(f"[score] file+CWE overall: "
          f"P={ov['precision']} R={ov['recall']} F1={ov['f1']} "
          f"(TP={ov['tp']} FP={ov['fp']} FN={ov['fn']} TN={ov['tn']})")


if __name__ == "__main__":
    main()
