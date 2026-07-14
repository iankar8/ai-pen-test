# ai-pen-test benchmark

A reproducible head-to-head: **ai-pen-test** vs **Semgrep** and **CodeQL** on
third-party labeled ground truth. The point is not to win. It is to be
*checkable*. A skeptic should be able to `git clone`, fetch the same datasets at
the same commits, run the same commands, and get the same baseline numbers.

> **Honesty contract.** No number in this benchmark is estimated, extrapolated,
> or hand-tuned. Every metric comes from a tool run recorded under `results/`.
> Where a run could not be executed — the ai-pen-test LLM pass needs a paid API
> key, and CodeQL's Java path needs a JDK that was absent on the build host — the
> cell reads **PENDING** or **BLOCKED**, never a plausible-looking guess. The
> scorer itself refuses to emit metrics it cannot compute (see Match criteria).

## Why this design

Every vendor SAST benchmark that got torn apart controlled its own test cases or
its own scoring. Every one that held up borrowed ground truth the tool author
could not tune to. So this benchmark uses **only external, published, labeled
corpora Ian did not author**, runs each baseline at its **recommended config**,
publishes the **exact commands and raw output** rather than a summary table, and
**discloses the categories where the baselines win**. Credibility here comes
from honesty and reproducibility, not from a clean sweep — a clean sweep would
read as fabricated, because in this domain it usually is.

## Datasets (ground truth we did NOT author)

| Corpus | Language | Commit | Role | Measures |
|---|---|---|---|---|
| OWASP BenchmarkJava — seeded 400-case subset | Java | `79b9bd6177e07991a9c11dc19e457c840e229931` | "synthetic corner" | precision / recall / F1 **+ Youden** (has true negatives) |
| SecurityEval | Python | `6f4fb70f782c6d47b02ea24341e8ef8c1eb04a6a` | recall-oriented | **recall only** (labeled-insecure only; no clean samples → precision/FPR undefined) |

- **OWASP BenchmarkJava** ships `expectedresults-1.2.csv` (2,740 Java cases, 1,415
  vulnerable / 1,325 safe). We score a **seeded (seed=42) stratified subset of 400**,
  proportional per `(category, is_vulnerable)` stratum — it preserves both the
  category mix and the vulnerable/safe balance and is the only corpus here with a
  true-negative population, so Youden's Index is computed only on it. Selection
  script: `scripts/build_owasp_index.py`. **Contamination caveat:** OWASP Benchmark
  is old and public; frontier LLMs may have seen it in pretraining, so it is the
  "synthetic corner," not the headline.
- **SecurityEval** is 121 Python samples across 69 CWEs, **every one labeled
  insecure**. It has no clean/benign files, so it measures **recall only** — it
  structurally cannot produce a Python precision or false-positive number, and this
  benchmark does not invent one. A clean-Python FP corpus (RealVuln's FP traps is
  the intended source) is the documented next addition; until it lands, the Python
  precision/FP column stays PENDING. See `datasets/README.md`.

Both corpora are large and **gitignored** (`benchmark/datasets/`). Regenerate:

```bash
bash benchmark/scripts/fetch_datasets.sh
/Users/iankar/ai-pen-test/.venv/bin/python benchmark/scripts/build_owasp_index.py
/Users/iankar/ai-pen-test/.venv/bin/python benchmark/scripts/build_securityeval_index.py
```

`fetch_datasets.sh` does shallow clones; re-running may resolve newer HEADs. Re-check
the printed `[commit]` lines against the table above and in `datasets/README.md`.

## Baseline configurations (fair config, disclosed)

- **Semgrep 1.169.0, Community Edition, `--config auto`.** `auto` pulls the free
  Registry ruleset. **CE disclosure:** ai-pen-test reasons across files; Semgrep CE
  does not (no Pro engine, no cross-file dataflow). Comparing to CE *without saying
  so* would be a strawman, so every Semgrep envelope records
  `edition: "CE"` and the config string. `auto` requires metrics enabled; the runner
  sets that and records it in the invocation.
- **CodeQL 2.26.0, `security-extended` query suite.** Python runs at
  `build-mode: none` (trivial, no compile). The Java/OWASP path needs a compiled
  database (autobuild → Maven + JDK); that toolchain was **absent on this build host**,
  so CodeQL-on-Java is reported **BLOCKED**, not silently dropped, with the exact
  failure and the command to complete it locally.

## Match criteria

Every tool is scored at **two granularities**, and the scorer will not fabricate a
metric it has no ground truth for:

- **file+CWE** (headline) — a ground-truth entry counts as detected if the tool
  produced ≥1 finding in that file with the same CWE. Fair across tools that report
  at different line granularity.
- **strict line-match** (±3 lines, secondary) — additionally requires the finding
  line within ±3 of the labelled line. The OWASP and SecurityEval indexes are
  per-file (one vuln per file, no line labels), so line-match is reported as
  **null / PENDING** for both — the scorer emits `null` with a reason rather than a
  fabricated line-match number. A line-labeled corpus is required to fill it.

The scorer also returns `null` (with a reason, never a 0) when precision/FPR/Youden
are undefined because a bucket has no safe samples (the SecurityEval case), and when
a bucket has no positive predictions. Its arithmetic is gated by
`tests/test_score.py`, a hand-computed fixture that must reproduce exactly.

## Nondeterminism plan (3 runs for variance)

LLM SAST is not deterministic even at temperature 0; self-agreement can drift 12–20%
run to run. So the ai-pen-test pass is specified as **3 runs per file at temp 0**,
reporting **mean ± range plus a per-finding stability %** across the three runs. The
model ID and access date are pinned in each envelope. Baselines (Semgrep, CodeQL) are
deterministic and run once. See `RUN_PAID_PASS.md` for the exact 3-run sequence.

## Credibility contract (the checklist that makes or breaks it)

1. Ground truth Ian did not author. ✅ (OWASP, SecurityEval — both external)
2. Baselines at recommended config, CE-vs-Pro disclosed. ✅
3. Commands + raw output published, not just a table. ✅ (`results/*.json`, `*.findings.json`)
4. Losses disclosed. ✅ (see the baseline-wins note below; ai-pen-test losses to be
   filled honestly once the paid pass runs)
5. Multiple runs with variance. ⏳ (3-run plan specified; executes in the paid pass)
6. Match criteria defined, strict + lenient. ✅ (file+CWE and line-match)
7. Contamination risk on old public datasets noted. ✅ (OWASP de-leak caveat)
8. No blanket "LLM beats SAST." ✅ (bounded-edge framing only)

---

## RESULTS

**Baseline columns are REAL** — reproduced from `results/*.json`, regenerable by
re-running the commands below. **The ai-pen-test columns are PENDING for every row:**
the shipped engine (`handlers/sast_analyzer.py`) makes paid LLM calls that need an
`OPENROUTER_API_KEY` (or `ANTHROPIC_API_KEY`), which was **not present in this
environment**. Filling them is a deliberate, separate step — see `RUN_PAID_PASS.md`,
estimated cost **~$100–300** for the two models below (batchable). No ai-pen-test
number appears here until Ian runs that pass; the pipeline that will produce them is
verified below by a zero-spend dry run.

The pass runs the engine under two models and reports a column for each:
`claude-3.7-sonnet` (the tool's shipped default) and `gpt-5.6-sol` (OpenAI flagship,
`openai/gpt-5.6-sol`). **Fairness note:** 3.7-sonnet is an older model than GPT-5.6 Sol,
so read a Claude-vs-GPT gap as "does upgrading the model help this tool," not "GPT is
better at security." For a same-generation comparison, add `claude-opus-4.5` (see
`RUN_PAID_PASS.md`).

### Overall (file+CWE granularity)

| Dataset | ai-pen-test (claude-3.7) | ai-pen-test (gpt-5.6-sol) | Semgrep CE 1.169.0 | CodeQL 2.26.0 |
|---|---|---|---|---|
| OWASP subset (400, Java) | **PENDING** | **PENDING** | P 0.673 / R 0.811 / F1 0.736 / Youden 0.393 | **BLOCKED** — no JDK/Maven on host |
| SecurityEval (121, Python) — recall-only | **PENDING** | **PENDING** | R 0.190 (23/121) | R 0.306 (37/121) |

Semgrep OWASP confusion: TP 167 / FP 81 / FN 39 / TN 113. Line-match: PENDING for all
rows (per-file ground truth has no line labels).

### OWASP per-CWE (Semgrep real; P / R / F1 / Youden)

| CWE | ai-pen-test (claude-3.7) | ai-pen-test (gpt-5.6-sol) | Semgrep CE | CodeQL |
|---|---|---|---|---|
| CWE-22 (path traversal) | PENDING | PENDING | 0.548 / 0.895 / 0.68 / 0.195 | BLOCKED |
| CWE-78 (OS command injection) | PENDING | PENDING | 0.529 / 1.0 / 0.692 / 0.111 | BLOCKED |
| CWE-79 (XSS) | PENDING | PENDING | 0.612 / 0.833 / 0.706 / 0.2 | BLOCKED |
| CWE-89 (SQL injection) | PENDING | PENDING | 0.627 / 0.925 / 0.747 / 0.278 | BLOCKED |
| CWE-90 (LDAP injection) | PENDING | PENDING | 0.444 / 1.0 / 0.615 / 0.0 | BLOCKED |
| CWE-327 (broken crypto) | PENDING | PENDING | — / 0.0 / — / 0.0 | BLOCKED |
| CWE-328 (weak hash) | PENDING | PENDING | 1.0 / 0.737 / 0.848 / 0.737 | BLOCKED |
| CWE-330 (weak randomness) | PENDING | PENDING | 1.0 / 1.0 / 1.0 / 1.0 | BLOCKED |
| CWE-501 (trust boundary) | PENDING | PENDING | 0.8 / 0.667 / 0.727 / 0.333 | BLOCKED |
| CWE-614 (insecure cookie) | PENDING | PENDING | 1.0 / 1.0 / 1.0 / 1.0 | BLOCKED |
| CWE-643 (XPath injection) | PENDING | 0.4 / 1.0 / 0.571 / 0.0 | BLOCKED |

### SecurityEval per-CWE (recall only; union of CWEs where ≥1 baseline detected)

| CWE | ai-pen-test | Semgrep CE (R) | CodeQL (R) |
|---|---|---|---|
| CWE-20 (n=6) | PENDING | 0.0 | 0.333 |
| CWE-22 (n=4) | PENDING | 0.25 | 0.75 |
| CWE-78 (n=2) | PENDING | 1.0 | 0.5 |
| CWE-79 (n=3) | PENDING | 1.0 | 1.0 |
| CWE-89 (n=2) | PENDING | 1.0 | 0.0 |
| CWE-90 (n=2) | PENDING | 0.0 | 1.0 |
| CWE-94 (n=3) | PENDING | 0.0 | 0.667 |
| CWE-95 (n=1) | PENDING | 1.0 | 0.0 |
| CWE-116 (n=2) | PENDING | 0.0 | 0.5 |
| CWE-117 (n=3) | PENDING | 0.0 | 0.333 |
| CWE-209 (n=1) | PENDING | 0.0 | 1.0 |
| CWE-215 (n=1) | PENDING | 0.0 | 1.0 |
| CWE-295 (n=3) | PENDING | 0.333 | 0.333 |
| CWE-319 (n=2) | PENDING | 0.5 | 0.0 |
| CWE-326 (n=2) | PENDING | 1.0 | 1.0 |
| CWE-327 (n=4) | PENDING | 0.25 | 1.0 |
| CWE-377 (n=1) | PENDING | 0.0 | 1.0 |
| CWE-502 (n=4) | PENDING | 1.0 | 0.25 |
| CWE-601 (n=5) | PENDING | 0.6 | 0.4 |
| CWE-611 (n=6) | PENDING | 0.0 | 0.333 |
| CWE-643 (n=2) | PENDING | 0.0 | 0.5 |
| CWE-730 (n=3) | PENDING | 0.0 | 0.667 |
| CWE-732 (n=1) | PENDING | 0.0 | 1.0 |
| CWE-776 (n=1) | PENDING | 0.0 | 1.0 |
| CWE-918 (n=2) | PENDING | 1.0 | 1.0 |

**The remaining 44 SecurityEval CWEs had recall 0.0 for BOTH Semgrep and CodeQL**
(neither pattern nor query baseline flagged them): CWE-80, 99, 113, 193, 200, 250,
252, 259, 269, 283, 285, 306, 321, 329, 330, 331, 339, 347, 367, 379, 385, 400, 406,
414, 425, 434, 454, 462, 477, 521, 522, 595, 605, 641, 703, 759, 760, 798, 827, 835,
841, 941, 943, 1204. These 44 categories are exactly where a semantic tool has room
to add value — but that remains **PENDING** until the paid pass produces real
ai-pen-test recall on them. No claim is made here.

### Mandatory note — categories where a baseline wins (to be confirmed)

The runbook requires disclosing ≥1 category where a pattern/query baseline beats
ai-pen-test; a benchmark with no baseline wins reads as fabricated. On real runs so
far the baselines are already strong exactly where pattern tools should be:

- **Semgrep CE nails the deterministic-pattern CWEs on OWASP:** CWE-330 (weak
  randomness) and CWE-614 (insecure cookie flag) at **P/R/F1/Youden = 1.0**, and
  CWE-328 (weak hash) at **F1 0.848 / Youden 0.737**. These are textbook,
  single-token patterns — cheap and reliable for a rules engine.
- **CodeQL's `security-extended` outrecalls Semgrep CE on several SecurityEval
  categories** (e.g. CWE-22 0.75 vs 0.25, CWE-611 0.333 vs 0.0, CWE-94 0.667 vs 0.0).

The honest expected shape is therefore "ai-pen-test wins on semantic / business-logic
categories, ties or loses on deterministic-pattern categories like weak-RNG,
weak-hash, and insecure-cookie." **This can only be confirmed once real ai-pen-test
numbers exist** — until the paid pass runs, the baseline-wins claim stands only for
the baselines against each other, not against ai-pen-test.

---

## Reproduce

### Baselines (no API key, real numbers above)

```bash
PY=/Users/iankar/ai-pen-test/.venv/bin/python

# Semgrep CE (one-time: $PY -m pip install semgrep)
$PY benchmark/runners/semgrep_runner.py \
    --index benchmark/datasets/owasp_subset.json \
    --target-root benchmark/datasets/BenchmarkJava \
    --out benchmark/results/semgrep_owasp.findings.json
$PY benchmark/score.py \
    --index benchmark/datasets/owasp_subset.json \
    --findings benchmark/results/semgrep_owasp.findings.json \
    --tool semgrep --dataset owasp

$PY benchmark/runners/semgrep_runner.py \
    --index benchmark/datasets/securityeval_index.json \
    --target-root benchmark/datasets/SecurityEval \
    --out benchmark/results/semgrep_securityeval.findings.json
$PY benchmark/score.py \
    --index benchmark/datasets/securityeval_index.json \
    --findings benchmark/results/semgrep_securityeval.findings.json \
    --tool semgrep --dataset securityeval

# CodeQL Python (build-mode none; CLI bundle in benchmark/tools/codeql, gitignored)
PATH=benchmark/tools/codeql:$PATH $PY benchmark/runners/codeql_runner.py \
    --index benchmark/datasets/securityeval_index.json \
    --target-root benchmark/datasets/SecurityEval \
    --language python --build-mode none \
    --out benchmark/results/codeql_securityeval.findings.json
$PY benchmark/score.py \
    --index benchmark/datasets/securityeval_index.json \
    --findings benchmark/results/codeql_securityeval.findings.json \
    --tool codeql --dataset securityeval

# CodeQL Java (BLOCKED on this host — needs JDK 17+ and Maven):
#   brew install openjdk maven
#   PATH=benchmark/tools/codeql:$PATH $PY benchmark/runners/codeql_runner.py \
#       --index benchmark/datasets/owasp_subset.json \
#       --target-root benchmark/datasets/BenchmarkJava \
#       --language java --build-mode autobuild \
#       --out benchmark/results/codeql_owasp.findings.json
```

### Scorer self-test (hard gate)

```bash
/Users/iankar/ai-pen-test/.venv/bin/python -m pytest benchmark/tests/test_score.py -v
```

### ai-pen-test dry run (zero spend — verifies the pipeline, NOT a result)

The dry run proves the full `dataset → engine runner → scorer` path works end to end
without spending anything. It emits **deterministic MOCK findings** (tagged
`mock: true`, envelope `dry_run: true`); the scorer surfaces a loud warning so mock
scores can never be mistaken for real ones. The runner never imports the engine or
any network client in mock mode — zero spend is structural, not promised.

```bash
PY=/Users/iankar/ai-pen-test/.venv/bin/python
$PY benchmark/scripts/build_handful_subsets.py     # deterministic 10-case subsets

$PY benchmark/runners/ai_pen_test_runner.py \
    --index benchmark/datasets/securityeval_handful.json \
    --target-root benchmark/datasets/SecurityEval \
    --out benchmark/results/ai_pen_test_DRYRUN_securityeval.findings.json --dry-run
$PY benchmark/score.py \
    --index benchmark/datasets/securityeval_handful.json \
    --findings benchmark/results/ai_pen_test_DRYRUN_securityeval.findings.json \
    --tool ai_pen_test_DRYRUN --dataset securityeval \
    --out benchmark/results/ai_pen_test_DRYRUN_securityeval.json
```

The scored DRYRUN files (`results/ai_pen_test_DRYRUN_*.json`) carry
`findings_provenance.dry_run = true` and a first note reading *"SOURCE FINDINGS ARE A
DRY-RUN/MOCK … NOT a real engine result."* Their metric values are meaningless mock
stubs and appear in **no results table** — they exist only to prove the plumbing.

### ai-pen-test real pass (fills the PENDING column — costs money)

See **`RUN_PAID_PASS.md`** for the exact `OPENROUTER_API_KEY` 3-run sequence and how
its output drops into the tables above.
