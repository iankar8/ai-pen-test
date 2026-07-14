#!/usr/bin/env python3
"""
build_handful_subsets.py — deterministic tiny subsets for the DRY-RUN pipeline check.

The DRY-RUN pass (see RUN_PAID_PASS.md / README.md) proves the full
dataset -> engine runner -> scorer path works end to end at ZERO spend, over a
handful of cases from each dataset rather than the full corpora. This script
regenerates those handful index files deterministically (seed=42) so the DRY-RUN
is reproducible from checked-in code, even though the index files themselves land
under the gitignored benchmark/datasets/ directory.

Run the full-index builders first (they produce the inputs this reads):
    python benchmark/scripts/build_owasp_index.py
    python benchmark/scripts/build_securityeval_index.py
    python benchmark/scripts/build_handful_subsets.py

Outputs:
    benchmark/datasets/securityeval_handful.json  (10 cases, distinct CWEs)
    benchmark/datasets/owasp_handful.json         (10 cases, category spread, vuln/safe mix)
"""

from __future__ import annotations

import json
import random
from pathlib import Path

SEED = 42
DATASETS = Path(__file__).resolve().parents[1] / "datasets"


def _pick_spread(entries, key, n, seed):
    """Deterministically pick one entry per distinct `key`, then take the first n."""
    rng = random.Random(seed)
    buckets = {}
    for e in entries:
        buckets.setdefault(e[key], []).append(e)
    picked = [rng.choice(v) for v in buckets.values()]
    rng.shuffle(picked)
    return picked[:n]


def main() -> None:
    se = json.loads((DATASETS / "securityeval_index.json").read_text())
    se_hand = _pick_spread(se, "cwe", 10, SEED)
    (DATASETS / "securityeval_handful.json").write_text(json.dumps(se_hand, indent=2))
    print(f"securityeval_handful.json: {len(se_hand)} cases, "
          f"CWEs {sorted({e['cwe'] for e in se_hand})}")

    ow = json.loads((DATASETS / "owasp_subset.json").read_text())
    ow_hand = _pick_spread(ow, "category", 10, SEED)
    (DATASETS / "owasp_handful.json").write_text(json.dumps(ow_hand, indent=2))
    vuln = sum(1 for e in ow_hand if e["is_vulnerable"])
    print(f"owasp_handful.json: {len(ow_hand)} cases, {vuln} vulnerable / "
          f"{len(ow_hand) - vuln} safe, CWEs {sorted({e['cwe'] for e in ow_hand})}")


if __name__ == "__main__":
    main()
