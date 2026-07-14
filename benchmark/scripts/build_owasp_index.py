#!/usr/bin/env python3
"""
build_owasp_index.py — parse OWASP BenchmarkJava expectedresults into a benchmark index,
then produce a SEEDED (seed=42) stratified ~400-case subset.

Ground truth we did NOT author. The CSV ships the CWE per test case directly; we also
keep an explicit category->CWE map so the mapping is auditable and any CSV/map mismatch
is surfaced rather than silently trusted.

Outputs (in benchmark/datasets/, gitignored):
  - owasp_index.json   : full list of {id, file, cwe, is_vulnerable, category}
  - owasp_subset.json  : seeded stratified subset (~400), proportional per (category, is_vulnerable)

Stratification: strata = (category, is_vulnerable). Proportional allocation via largest-remainder
so the subset preserves both category mix AND the vulnerable/non-vulnerable balance within each
category. seed=42 fixed for reproducibility.
"""

import csv
import json
import random
from pathlib import Path

SEED = 42
TARGET_SUBSET = 400

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"
BENCH_DIR = DATASETS_DIR / "BenchmarkJava"
CSV_PATH = BENCH_DIR / "expectedresults-1.2.csv"
TESTCODE_REL = "src/main/java/org/owasp/benchmark/testcode"

# Explicit, auditable category -> CWE map (verified against the CSV's own cwe column).
CATEGORY_CWE = {
    "pathtraver": 22,
    "hash": 328,
    "crypto": 327,
    "sqli": 89,
    "weakrand": 330,
    "xss": 79,
    "cmdi": 78,
    "trustbound": 501,
    "securecookie": 614,
    "ldapi": 90,
    "xpathi": 643,
}


def load_rows():
    rows = []
    with open(CSV_PATH, newline="") as f:
        for raw in f:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            parts = [p.strip() for p in raw.split(",")]
            test_name, category, real_vuln, cwe = parts[0], parts[1], parts[2], int(parts[3])
            # Audit: CSV cwe must agree with our explicit map.
            if category not in CATEGORY_CWE:
                raise SystemExit(f"Unknown category in CSV: {category}")
            if CATEGORY_CWE[category] != cwe:
                raise SystemExit(
                    f"CWE mismatch for {test_name}: CSV={cwe} map={CATEGORY_CWE[category]}"
                )
            is_vuln = real_vuln.lower() == "true"
            java_file = f"{TESTCODE_REL}/{test_name}.java"
            abs_file = BENCH_DIR / f"{test_name}.java"
            # sanity: testcase file exists on disk
            if not (BENCH_DIR / TESTCODE_REL / f"{test_name}.java").exists():
                raise SystemExit(f"Missing testcase file for {test_name}")
            rows.append(
                {
                    "id": test_name,
                    "file": java_file,
                    "cwe": cwe,
                    "is_vulnerable": is_vuln,
                    "category": category,
                }
            )
    return rows


def build_subset(rows):
    # strata keyed by (category, is_vulnerable)
    strata = {}
    for r in rows:
        strata.setdefault((r["category"], r["is_vulnerable"]), []).append(r)

    total = len(rows)
    # largest-remainder proportional allocation
    exact = {k: len(v) / total * TARGET_SUBSET for k, v in strata.items()}
    alloc = {k: int(v) for k, v in exact.items()}
    remainder = TARGET_SUBSET - sum(alloc.values())
    # distribute remaining slots to largest fractional parts
    fracs = sorted(strata.keys(), key=lambda k: exact[k] - alloc[k], reverse=True)
    for k in fracs[:remainder]:
        alloc[k] += 1

    rng = random.Random(SEED)
    subset = []
    for k in sorted(strata.keys()):
        pool = sorted(strata[k], key=lambda r: r["id"])  # deterministic order before shuffle
        n = min(alloc[k], len(pool))
        subset.extend(rng.sample(pool, n))
    subset.sort(key=lambda r: r["id"])
    return subset


def main():
    rows = load_rows()
    (DATASETS_DIR / "owasp_index.json").write_text(json.dumps(rows, indent=2))

    subset = build_subset(rows)
    (DATASETS_DIR / "owasp_subset.json").write_text(json.dumps(subset, indent=2))

    print(f"owasp_index.json: {len(rows)} cases")
    print(f"owasp_subset.json: {len(subset)} cases (seed={SEED}, target={TARGET_SUBSET})")

    print("\nPer-category counts (index -> subset):")
    def per_cat(items):
        d = {}
        for r in items:
            d[r["category"]] = d.get(r["category"], 0) + 1
        return d
    idx_cat, sub_cat = per_cat(rows), per_cat(subset)
    print(f"  {'category':<14} {'cwe':>5} {'index':>7} {'subset':>7}")
    for cat in sorted(idx_cat, key=lambda c: idx_cat[c], reverse=True):
        print(f"  {cat:<14} {CATEGORY_CWE[cat]:>5} {idx_cat[cat]:>7} {sub_cat.get(cat,0):>7}")

    print("\nSubset vulnerable/non-vulnerable balance:")
    v = sum(1 for r in subset if r["is_vulnerable"])
    print(f"  vulnerable={v}  non-vulnerable={len(subset)-v}")


if __name__ == "__main__":
    main()
