#!/usr/bin/env python3
"""
build_overnight_subset.py — smaller seeded-stratified indexes for the $0 overnight
Codex-subscription run. The full corpus (521 files) at ~100s/file via codex exec is
~15h; this trims to ~180 files (~5h) while keeping per-CWE coverage on both datasets.

Deterministic: seed=42, proportional per (cwe, is_vulnerable) for OWASP and per cwe
for SecurityEval. Writes owasp_overnight.json (~100) + securityeval_overnight.json (~80).
"""
import json, random
from collections import defaultdict
from pathlib import Path

DS = Path(__file__).resolve().parents[1] / "datasets"
SEED = 42
OWASP_TARGET = 100
SECEVAL_TARGET = 80


def stratified(items, keyfn, target):
    groups = defaultdict(list)
    for it in items:
        groups[keyfn(it)].append(it)
    rng = random.Random(SEED)
    for g in groups.values():
        g.sort(key=lambda x: x["id"])   # stable order before shuffle
        rng.shuffle(g)
    frac = target / len(items)
    out = []
    for g in groups.values():
        k = max(1, round(len(g) * frac))
        out.extend(g[:k])
    out.sort(key=lambda x: x["id"])
    return out


def main():
    owasp = json.load(open(DS / "owasp_subset.json"))
    seceval = json.load(open(DS / "securityeval_index.json"))

    o = stratified(owasp, lambda x: (x["cwe"], x["is_vulnerable"]), OWASP_TARGET)
    s = stratified(seceval, lambda x: x["cwe"], SECEVAL_TARGET)

    json.dump(o, open(DS / "owasp_overnight.json", "w"), indent=2)
    json.dump(s, open(DS / "securityeval_overnight.json", "w"), indent=2)

    ov = sum(1 for x in o if x["is_vulnerable"])
    print(f"owasp_overnight.json:       {len(o)} files ({ov} vuln / {len(o)-ov} safe)")
    print(f"securityeval_overnight.json:{len(s)} files ({len(set(x['cwe'] for x in s))} CWEs)")
    print(f"total ~{len(o)+len(s)} files  (~{round((len(o)+len(s))*100/3600,1)}h at ~100s/file)")


if __name__ == "__main__":
    main()
