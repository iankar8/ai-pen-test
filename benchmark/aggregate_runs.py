#!/usr/bin/env python3
"""
aggregate_runs.py — combine N runs of one tool on one dataset into the variance
figures the runbook requires (mean ± range + a per-finding stability %).

LLM SAST is not deterministic even at temperature 0, so the ai-pen-test pass runs
each dataset 3×. This script takes those N findings envelopes plus the dataset
index and reports, per metric:

  * mean, min, max across the N runs (the "mean ± range")
  * finding stability: of every distinct (file, CWE) a run ever reported, the
    fraction that appeared in ALL N runs (1.0 = perfectly stable, lower = drift)

It fabricates nothing: with fewer than 2 runs it refuses (no variance to report),
and any metric the scorer returns as null (undefined) is carried through as null.

Usage:
    python benchmark/aggregate_runs.py \
        --index benchmark/datasets/securityeval_index.json \
        --tool ai_pen_test --dataset securityeval \
        --runs benchmark/results/ai_pen_test_securityeval.run1.findings.json \
               benchmark/results/ai_pen_test_securityeval.run2.findings.json \
               benchmark/results/ai_pen_test_securityeval.run3.findings.json \
        --out benchmark/results/ai_pen_test_securityeval.aggregate.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional

from score import compute_scores

METRICS = ("precision", "recall", "f1", "tpr", "fpr", "youden")


def _load_findings(path: str) -> List[Dict[str, Any]]:
    doc = json.loads(Path(path).read_text())
    return doc.get("findings", doc) if isinstance(doc, dict) else doc


def _summ(values: List[Optional[float]]) -> Dict[str, Any]:
    present = [v for v in values if v is not None]
    if not present:
        return {"mean": None, "min": None, "max": None,
                "runs_defined": 0, "note": "undefined in all runs"}
    return {
        "mean": mean(present),
        "min": min(present),
        "max": max(present),
        "runs_defined": len(present),
    }


def _finding_stability(run_findings: List[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Fraction of distinct (file, cwe) pairs reported in ALL runs vs. in ANY run."""
    def norm(path: str) -> str:
        return str(path).replace("\\", "/").lstrip("./")

    per_run_sets = [
        {(norm(f.get("file", "")), f.get("cwe")) for f in fs}
        for fs in run_findings
    ]
    any_set: set = set().union(*per_run_sets) if per_run_sets else set()
    if not any_set:
        return {"stability": None, "note": "no findings in any run", "in_all": 0, "in_any": 0}
    all_set = set(per_run_sets[0])
    for s in per_run_sets[1:]:
        all_set &= s
    return {
        "stability": len(all_set) / len(any_set),
        "in_all": len(all_set),
        "in_any": len(any_set),
        "note": f"{len(all_set)} of {len(any_set)} distinct (file,CWE) findings "
                f"appeared in all {len(run_findings)} runs",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Aggregate N runs into mean +/- range + stability.")
    ap.add_argument("--index", required=True)
    ap.add_argument("--runs", nargs="+", required=True, help="N findings envelopes")
    ap.add_argument("--tool", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--tolerance", type=int, default=3)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if len(args.runs) < 2:
        ap.error("need >= 2 runs to report variance (this is a variance tool; "
                 "with one run, score.py already gives the point estimate)")

    ground_truth = json.loads(Path(args.index).read_text())
    run_findings = [_load_findings(p) for p in args.runs]

    per_run_scores = [
        compute_scores(ground_truth, fs, line_tolerance=args.tolerance,
                       tool=args.tool, dataset=args.dataset)
        for fs in run_findings
    ]

    # Aggregate the file+CWE overall metrics across runs.
    overall_across = {
        m: _summ([s["file_cwe_match"]["overall"][m] for s in per_run_scores])
        for m in METRICS
    }

    # Aggregate per-CWE recall (the metric every corpus can produce).
    cwes = sorted({c for s in per_run_scores for c in s["file_cwe_match"]["per_cwe"]}, key=int)
    per_cwe_recall = {
        c: _summ([s["file_cwe_match"]["per_cwe"].get(c, {}).get("recall")
                  for s in per_run_scores])
        for c in cwes
    }

    result = {
        "tool": args.tool,
        "dataset": args.dataset,
        "n_runs": len(args.runs),
        "run_files": args.runs,
        "granularity": "file_cwe",
        "overall_mean_range": overall_across,
        "per_cwe_recall_mean_range": per_cwe_recall,
        "finding_stability": _finding_stability(run_findings),
        "note": ("mean +/- [min,max] across runs; recall is the metric reported "
                 "per CWE because SecurityEval is recall-only. Any metric undefined "
                 "in a run (null) is excluded from that run's aggregate, not "
                 "counted as 0."),
    }

    out = args.out or str(Path(__file__).parent / "results" /
                          f"{args.tool}_{args.dataset}.aggregate.json")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(result, indent=2))
    o = overall_across
    print(f"[aggregate] {args.tool}/{args.dataset} over {len(args.runs)} runs -> {out}")
    print(f"[aggregate] recall mean={o['recall']['mean']} "
          f"range=[{o['recall']['min']},{o['recall']['max']}]  "
          f"stability={result['finding_stability']['stability']}")


if __name__ == "__main__":
    main()
