#!/usr/bin/env python3
"""
test_score.py — HARD GATE for the benchmark.

The scorer's arithmetic is the credibility foundation of the whole benchmark: if
precision/recall/F1 are wrong, every published number is wrong. So this test uses
a TINY, hand-constructed ground-truth + findings set whose confusion matrix and
metrics are worked out BY HAND in the comments below, then asserts score.py
reproduces them exactly.

Run:
    /Users/iankar/ai-pen-test/.venv/bin/python -m pytest benchmark/tests/test_score.py -v
"""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from score import compute_scores, metrics_from_counts  # noqa: E402


def approx(a, b, tol=1e-9):
    if a is None or b is None:
        return a is None and b is None
    return math.isclose(a, b, rel_tol=0, abs_tol=tol)


# ---------------------------------------------------------------------------
# Hand-built fixture
# ---------------------------------------------------------------------------
# Ground truth (5 entries, mixed vulnerable/safe, two CWEs, lines on vuln ones):
#   e1  a.py  CWE-89  vulnerable   line 10
#   e2  b.py  CWE-89  vulnerable   line 20
#   e3  c.py  CWE-79  vulnerable   line 5
#   e4  d.py  CWE-89  NOT vuln     (safe version)
#   e5  e.py  CWE-79  NOT vuln     (safe version)
GROUND_TRUTH = [
    {"id": "e1", "file": "a.py", "cwe": 89, "is_vulnerable": True,  "line": 10},
    {"id": "e2", "file": "b.py", "cwe": 89, "is_vulnerable": True,  "line": 20},
    {"id": "e3", "file": "c.py", "cwe": 79, "is_vulnerable": True,  "line": 5},
    {"id": "e4", "file": "d.py", "cwe": 89, "is_vulnerable": False},
    {"id": "e5", "file": "e.py", "cwe": 79, "is_vulnerable": False},
]

# Tool findings (normalized):
#   a.py CWE-89 line 11   -> e1: file+cwe match; |11-10|=1 <= 3  -> line match too
#   b.py CWE-89 line 30   -> e2: file+cwe match; |30-20|=10 > 3  -> NO line match
#   c.py CWE-22 line 5    -> e3: file matches but CWE 22 != 79   -> NOT detected
#   d.py CWE-89 line 1    -> e4: file+cwe match on a SAFE file   -> false positive
#   (nothing on e.py)
FINDINGS = [
    {"file": "a.py", "line": 11, "cwe": 89, "severity": "HIGH"},
    {"file": "b.py", "line": 30, "cwe": 89, "severity": "HIGH"},
    {"file": "c.py", "line": 5,  "cwe": 22, "severity": "MEDIUM"},
    {"file": "d.py", "line": 1,  "cwe": 89, "severity": "HIGH"},
]


# ===========================================================================
# file+CWE granularity — BY HAND
# ===========================================================================
# e1 TP, e2 TP, e3 FN (cwe mismatch), e4 FP (safe file flagged), e5 TN
# Overall: TP=2 FP=1 FN=1 TN=1
#   precision = 2/(2+1) = 0.666666...
#   recall    = 2/(2+1) = 0.666666...
#   f1        = 2PR/(P+R) = 2(0.4444..)/(1.3333..) = 0.666666...
#   tpr = 0.6666.. ; fpr = FP/(FP+TN) = 1/2 = 0.5 ; youden = 0.16666..
def test_file_cwe_overall():
    r = compute_scores(GROUND_TRUTH, FINDINGS)["file_cwe_match"]["overall"]
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (2, 1, 1, 1)
    assert approx(r["precision"], 2 / 3)
    assert approx(r["recall"], 2 / 3)
    assert approx(r["f1"], 2 / 3)
    assert approx(r["tpr"], 2 / 3)
    assert approx(r["fpr"], 0.5)
    assert approx(r["youden"], 2 / 3 - 0.5)


# Per-CWE 89: entries e1,e2 (vuln), e4 (safe).
#   e1 TP, e2 TP, e4 FP -> TP=2 FP=1 FN=0 TN=0
#   precision = 2/3 ; recall = 2/2 = 1.0 ; f1 = 2(2/3)(1)/(2/3+1) = (4/3)/(5/3) = 0.8
#   fpr = 1/(1+0) = 1.0 ; youden = 1.0 - 1.0 = 0.0
def test_file_cwe_per_cwe_89():
    r = compute_scores(GROUND_TRUTH, FINDINGS)["file_cwe_match"]["per_cwe"]["89"]
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (2, 1, 0, 0)
    assert approx(r["precision"], 2 / 3)
    assert approx(r["recall"], 1.0)
    assert approx(r["f1"], 0.8)
    assert approx(r["fpr"], 1.0)
    assert approx(r["youden"], 0.0)


# Per-CWE 79: entries e3 (vuln), e5 (safe).
#   e3 FN (cwe mismatch), e5 TN -> TP=0 FP=0 FN=1 TN=1
#   precision undefined (no positive predictions) -> None
#   recall = 0/1 = 0.0 ; f1 = None (precision None)
#   fpr = 0/1 = 0.0 ; tpr = 0.0 ; youden = 0.0
def test_file_cwe_per_cwe_79():
    r = compute_scores(GROUND_TRUTH, FINDINGS)["file_cwe_match"]["per_cwe"]["79"]
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (0, 0, 1, 1)
    assert r["precision"] is None
    assert approx(r["recall"], 0.0)
    assert r["f1"] is None
    assert approx(r["fpr"], 0.0)
    assert approx(r["tpr"], 0.0)
    assert approx(r["youden"], 0.0)


# ===========================================================================
# strict line-match granularity (tol = 3) — BY HAND
# ===========================================================================
# e1 (a.py,89,line10): finding line 11, |11-10|=1<=3 -> TP
# e2 (b.py,89,line20): finding line 30, |30-20|=10>3 -> FN
# e3 (c.py,79,line5):  finding cwe 22 != 79           -> FN
# e4 (d.py,89,safe):   finding cwe89 in file (line ignored for safe) -> FP
# e5 (e.py,79,safe):   nothing                         -> TN
# Overall: TP=1 FP=1 FN=2 TN=1
#   precision = 1/(1+1) = 0.5
#   recall    = 1/(1+2) = 0.333333...
#   f1        = 2(0.5)(0.3333..)/(0.8333..) = 0.4
#   tpr=0.3333.. ; fpr=1/2=0.5 ; youden = 0.3333.. - 0.5 = -0.16666..
def test_line_overall():
    r = compute_scores(GROUND_TRUTH, FINDINGS)["line_match"]["overall"]
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (1, 1, 2, 1)
    assert approx(r["precision"], 0.5)
    assert approx(r["recall"], 1 / 3)
    assert approx(r["f1"], 0.4)
    assert approx(r["tpr"], 1 / 3)
    assert approx(r["fpr"], 0.5)
    assert approx(r["youden"], 1 / 3 - 0.5)


# Per-CWE 89 (line): e1 TP, e2 FN, e4 FP -> TP=1 FP=1 FN=1 TN=0
#   precision = 1/2 = 0.5 ; recall = 1/2 = 0.5 ; f1 = 0.5
#   fpr = 1/1 = 1.0 ; youden = 0.5 - 1.0 = -0.5
def test_line_per_cwe_89():
    r = compute_scores(GROUND_TRUTH, FINDINGS)["line_match"]["per_cwe"]["89"]
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (1, 1, 1, 0)
    assert approx(r["precision"], 0.5)
    assert approx(r["recall"], 0.5)
    assert approx(r["f1"], 0.5)
    assert approx(r["fpr"], 1.0)
    assert approx(r["youden"], -0.5)


# ===========================================================================
# Recall-only corpus (no non-vulnerable samples) — the SecurityEval shape.
# ===========================================================================
# GT: two vulnerable-only entries, no line labels.
#   g1 x.py CWE-89 vuln ; g2 y.py CWE-79 vuln
# Findings: x.py CWE-89 (detects g1) ; nothing for g2.
#   TP=1 FN=1 FP=0 TN=0  (neg == 0)
#   precision = None (no non-vulnerable samples) ; fpr = None ; youden = None ; f1 = None
#   recall = 1/2 = 0.5
# Also: no vuln entry has a line -> line_match section must be None.
def test_recall_only_corpus():
    gt = [
        {"id": "g1", "file": "x.py", "cwe": 89, "is_vulnerable": True},
        {"id": "g2", "file": "y.py", "cwe": 79, "is_vulnerable": True},
    ]
    fnd = [{"file": "x.py", "line": 3, "cwe": 89, "severity": "HIGH"}]
    res = compute_scores(gt, fnd)
    ov = res["file_cwe_match"]["overall"]
    assert (ov["tp"], ov["fp"], ov["fn"], ov["tn"]) == (1, 0, 1, 0)
    assert ov["precision"] is None
    assert ov["fpr"] is None
    assert ov["youden"] is None
    assert ov["f1"] is None
    assert approx(ov["recall"], 0.5)
    # no line labels on vulnerable entries -> line_match is null (PENDING, not fabricated)
    assert res["line_match"] is None


# ===========================================================================
# Direct unit check of the metrics helper on a clean textbook matrix.
# TP=8 FP=2 FN=2 TN=8:
#   precision = 8/10 = 0.8 ; recall = 8/10 = 0.8 ; f1 = 0.8
#   fpr = 2/10 = 0.2 ; youden = 0.8 - 0.2 = 0.6
# ===========================================================================
def test_metrics_helper_textbook():
    m = metrics_from_counts(tp=8, fp=2, fn=2, tn=8)
    assert approx(m["precision"], 0.8)
    assert approx(m["recall"], 0.8)
    assert approx(m["f1"], 0.8)
    assert approx(m["fpr"], 0.2)
    assert approx(m["youden"], 0.6)
