# RUN_PAID_PASS.md — filling the ai-pen-test column

This is the one documented sequence that fills the **PENDING** ai-pen-test cells in
`README.md`. It costs money: the shipped engine (`handlers/sast_analyzer.py`) makes
LLM calls through OpenRouter. Nobody should run it by accident, so the runner will
not spend without a key — with no `OPENROUTER_API_KEY` it auto-falls back to the
zero-cost mock and says so.

## What it costs and what it uses

- **Key:** `OPENROUTER_API_KEY` (the runner also accepts `ANTHROPIC_API_KEY` for the
  direct-Anthropic path, but the shipped default is OpenRouter).
- **Models (multi-model):** the pass runs the engine under each model in `MODELS` and
  produces one column per model. Default: `claude-3.7-sonnet` (the tool's shipped
  default) and `gpt-5.6-sol` (OpenAI flagship, `openai/gpt-5.6-sol`). Called at
  **temperature 0**; the exact id + your run date land in each envelope's `config`.
  - **Fairness note:** `claude-3.7-sonnet` is the shipped default and is an *older*
    model than `gpt-5.6-sol` (Feb-2025 vs Jul-2026). So a Claude-3.7-vs-GPT-5.6 result
    reads as *"does upgrading the model help this tool,"* NOT *"GPT beats Claude at
    security."* For a same-generation head-to-head, add `claude-opus-4.5` to `MODELS`.
- **Cost:** approximately **$100–300** total (2 models). The engine calls the LLM per
  file; Claude 3.7 Sonnet and GPT-5.6 Sol are both ~$3–5 / $15–30 per M input/output
  tokens. Both datasets × 3 runs × 2 models is ~3,200 scans. Batchable at ~50% off.
  To spend less, run one model or drop to the 10-file handful index first.
- **Time:** dominated by the scan wait, not by your keyboard. Kick it off and leave it.

## Preconditions (once)

```bash
export OPENROUTER_API_KEY=sk-or-...     # your key; never commit it

# datasets present at the pinned commits (see README dataset table)
bash benchmark/scripts/fetch_datasets.sh
PY=/Users/iankar/ai-pen-test/.venv/bin/python
$PY benchmark/scripts/build_owasp_index.py
$PY benchmark/scripts/build_securityeval_index.py

# sanity: the scorer's arithmetic gate must pass before you trust any number
$PY -m pytest benchmark/tests/test_score.py -v
```

## The run (3 runs per dataset, for variance)

The runbook requires 3 runs at temp 0 because LLM SAST is not deterministic even at
temp 0 (self-agreement can drift 12–20%). Run each dataset three times into
`run1/2/3` findings envelopes, score each, then aggregate to mean ± range +
finding-stability.

> Full-corpus scale: SecurityEval = 121 files, OWASP subset = 400 files. To smoke-test
> the paid path on a few files first, swap `securityeval_index.json` for
> `securityeval_handful.json` (10 files) — same commands, ~1/12th the spend.

```bash
export OPENROUTER_API_KEY=sk-or-...
PY=/Users/iankar/ai-pen-test/.venv/bin/python
cd /Users/iankar/ai-pen-test

# Models to compare (edit this list). tool label uses the model id.
MODELS=("claude-3.7-sonnet" "gpt-5.6-sol")

for MODEL in "${MODELS[@]}"; do
  # ---- SecurityEval (Python), 3 runs ----
  for i in 1 2 3; do
    $PY benchmark/runners/ai_pen_test_runner.py \
        --index benchmark/datasets/securityeval_index.json \
        --target-root benchmark/datasets/SecurityEval \
        --model "$MODEL" \
        --out benchmark/results/ai_pen_test_${MODEL}_securityeval.run$i.findings.json
  done
  # ---- OWASP subset (Java), 3 runs ----
  for i in 1 2 3; do
    $PY benchmark/runners/ai_pen_test_runner.py \
        --index benchmark/datasets/owasp_subset.json \
        --target-root benchmark/datasets/BenchmarkJava \
        --model "$MODEL" \
        --out benchmark/results/ai_pen_test_${MODEL}_owasp.run$i.findings.json
  done
done
```

Each envelope carries `dry_run: false` and the exact model/config — that is your
proof the numbers are real. If any envelope says `dry_run: true`, the key was not
picked up; fix the environment and re-run rather than reporting it.

## Score each run, then aggregate

```bash
PY=/Users/iankar/ai-pen-test/.venv/bin/python
MODELS=("claude-3.7-sonnet" "gpt-5.6-sol")

for MODEL in "${MODELS[@]}"; do
  # score all six runs for this model
  for ds in securityeval owasp; do
    idx=$([ $ds = securityeval ] && echo securityeval_index.json || echo owasp_subset.json)
    for i in 1 2 3; do
      $PY benchmark/score.py \
          --index benchmark/datasets/$idx \
          --findings benchmark/results/ai_pen_test_${MODEL}_${ds}.run$i.findings.json \
          --tool "ai_pen_test:${MODEL}" --dataset $ds \
          --out benchmark/results/ai_pen_test_${MODEL}_${ds}.run$i.json
    done
  done
  # aggregate to mean +/- range + finding stability, per dataset
  for ds in securityeval owasp; do
    idx=$([ $ds = securityeval ] && echo securityeval_index.json || echo owasp_subset.json)
    $PY benchmark/aggregate_runs.py \
        --index benchmark/datasets/$idx \
        --tool "ai_pen_test:${MODEL}" --dataset $ds \
        --runs benchmark/results/ai_pen_test_${MODEL}_${ds}.run1.findings.json \
               benchmark/results/ai_pen_test_${MODEL}_${ds}.run2.findings.json \
               benchmark/results/ai_pen_test_${MODEL}_${ds}.run3.findings.json \
        --out benchmark/results/ai_pen_test_${MODEL}_${ds}.aggregate.json
  done
done
```

## Dropping the results into the README tables

`aggregate_runs.py` prints and writes, per dataset:

- `overall_mean_range.recall` (and precision/f1/youden where defined) — `mean`,
  `min`, `max` across the 3 runs.
- `per_cwe_recall_mean_range` — the same, per CWE.
- `finding_stability.stability` — the fraction of distinct (file, CWE) findings that
  appeared in all 3 runs.

Fill the README's **ai-pen-test** column with the file+CWE `mean` and show the range,
e.g. `R 0.42 [0.39–0.45]`, and add the stability % as a footnote to the table (e.g.
"ai-pen-test finding stability: 0.83 over 3 runs, SecurityEval"). Replace each
`PENDING` cell only with a value that traces to
`results/ai_pen_test_*.aggregate.json`. Leave any metric the aggregate reports as
`null` (undefined for that corpus) as `—`, not 0.

Then revisit the README's **"categories where a baseline wins"** note: once real
ai-pen-test per-CWE recall exists, confirm the ≥1 category where Semgrep/CodeQL still
beats it (the runbook forbids a clean sweep — if ai-pen-test appears to win
everywhere, treat that as a bug or contamination and investigate before publishing).
The honest expected shape is ai-pen-test ahead on semantic / business-logic CWEs,
behind on deterministic-pattern CWEs (weak-RNG CWE-330, weak-hash CWE-328, insecure
cookie CWE-614), with disclosed losses.

## Optional: complete the CodeQL Java cell

CodeQL-on-Java is **BLOCKED** in the shipped results (the build host had no JDK/Maven).
To fill it on a machine that has them:

```bash
brew install openjdk maven
PY=/Users/iankar/ai-pen-test/.venv/bin/python
PATH=benchmark/tools/codeql:$PATH $PY benchmark/runners/codeql_runner.py \
    --index benchmark/datasets/owasp_subset.json \
    --target-root benchmark/datasets/BenchmarkJava \
    --language java --build-mode autobuild \
    --out benchmark/results/codeql_owasp.findings.json
$PY benchmark/score.py \
    --index benchmark/datasets/owasp_subset.json \
    --findings benchmark/results/codeql_owasp.findings.json \
    --tool codeql --dataset owasp
```
