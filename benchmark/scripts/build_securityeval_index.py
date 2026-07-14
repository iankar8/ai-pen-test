#!/usr/bin/env python3
"""
build_securityeval_index.py — build a benchmark index over SecurityEval labeled-insecure Python.

SecurityEval (s2e-lab) ships one insecure Python sample per record in dataset.jsonl, keyed by
ID like "CWE-020_author_1.py". The corresponding insecure source lives at
Testcases_Insecure_Code/<CWE-XXX>/<author_1.py>. Every sample is labeled insecure, so this is a
RECALL-oriented corpus only (all is_vulnerable=true). Precision/FP needs a clean-code corpus,
which SecurityEval does not provide (documented TODO in datasets/README.md).

Output (benchmark/datasets/, gitignored):
  - securityeval_index.json : list of {id, file, cwe, is_vulnerable: true}
"""

import json
import re
from pathlib import Path

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"
SE_DIR = DATASETS_DIR / "SecurityEval"
JSONL = SE_DIR / "dataset.jsonl"
INSECURE_REL = "Testcases_Insecure_Code"

ID_RE = re.compile(r"^(CWE-(\d+))_(.+\.py)$")


def main():
    records = []
    with open(JSONL) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))

    out = []
    missing = []
    for rec in records:
        rid = rec["ID"]
        m = ID_RE.match(rid)
        if not m:
            raise SystemExit(f"Unparseable ID: {rid}")
        cwe_dir, cwe_num, leaf = m.group(1), int(m.group(2)), m.group(3)
        rel = f"{INSECURE_REL}/{cwe_dir}/{leaf}"
        if not (SE_DIR / rel).exists():
            missing.append(rid)
            continue
        out.append(
            {"id": rid, "file": rel, "cwe": cwe_num, "is_vulnerable": True}
        )

    (DATASETS_DIR / "securityeval_index.json").write_text(json.dumps(out, indent=2))

    print(f"securityeval_index.json: {len(out)} labeled-insecure Python samples")
    if missing:
        print(f"WARNING: {len(missing)} records had no matching insecure file: {missing}")

    dist = {}
    for r in out:
        dist[r["cwe"]] = dist.get(r["cwe"], 0) + 1
    print(f"\nCWE distribution ({len(dist)} distinct CWEs):")
    for cwe in sorted(dist, key=lambda c: (-dist[c], c)):
        print(f"  CWE-{cwe:<5} {dist[cwe]}")


if __name__ == "__main__":
    main()
