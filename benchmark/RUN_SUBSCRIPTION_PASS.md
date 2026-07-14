# RUN_SUBSCRIPTION_PASS.md — fill the ai-pen-test column on your Codex subscription

This runs the ai-pen-test model pass through the **Codex CLI**, so it bills against
your **ChatGPT/Codex subscription** (rate limits) instead of metered API credits.
Zero API spend. Runs on *your* machine — the Codex CLI must be installed and signed
in with ChatGPT.

## Read this first — the tradeoffs you accepted

- **Model = GPT-5.6 Luna, not Sol.** Sol exhausts the 5-hour Codex window in minutes
  (documented in the Codex issue tracker). Luna has ~5–6× the message allowance and
  fits the batch. Terra is a middle option. To use Sol anyway, expect multi-day
  windowed running and possible weekly-cap exhaustion.
- **This measures the "via-Codex-agent" config.** `codex exec` runs the Codex *agent*
  around ai-pen-test's prompt, not a raw single-turn completion. It uses the engine's
  own prompt + parser, but the agent wrapper makes it a slightly different measurement
  than the OpenRouter path. The results column is labeled accordingly.
- **It was written but not tested in the build environment** (the Codex binary was
  broken there). So: **run the smoke test first.**

## Step 0 — install + sign in + smoke test (do NOT skip)

```bash
# Codex CLI installed and signed in with ChatGPT (not an API key):
codex login            # choose ChatGPT sign-in
codex --version        # confirm it runs (the build host's binary was broken)

# One-scan format check — proves the backend works and shows codex's raw output
# shape before you spend a subscription window on 1,560 scans:
PY=/Users/iankar/ai-pen-test/.venv/bin/python
$PY benchmark/scripts/codex_smoke.py --model gpt-5.6-luna
```

If the smoke test parses findings, continue. If it prints raw output that clearly
contains JSON but parsed 0 findings, the parser needs to strip Codex's wrapper — send
that raw output and it's a one-line fix in `handlers/sast_analyzer.py::_call_codex`.

## Step 1 — the run (backend=codex, Luna, 3 runs for variance)

Mind the rate window: 1,560 scans (2 datasets × 3 runs × 260 avg files) will span
multiple 5-hour windows even on Luna/Pro-20x. Run one dataset, let the window reset,
run the next. Start with the 10-file handful to sanity-check end to end.

```bash
PY=/Users/iankar/ai-pen-test/.venv/bin/python
cd /Users/iankar/ai-pen-test
MODEL=gpt-5.6-luna

# smoke: 10 files end to end first
$PY benchmark/runners/ai_pen_test_runner.py \
    --index benchmark/datasets/securityeval_handful.json \
    --target-root benchmark/datasets/SecurityEval \
    --backend codex --model $MODEL \
    --out benchmark/results/ai_pen_test_${MODEL}_handful.run1.findings.json

# full: SecurityEval (Python) then OWASP (Java), 3 runs each
for ds in securityeval owasp; do
  idx=$([ $ds = securityeval ] && echo securityeval_index.json || echo owasp_subset.json)
  root=$([ $ds = securityeval ] && echo SecurityEval || echo BenchmarkJava)
  for i in 1 2 3; do
    $PY benchmark/runners/ai_pen_test_runner.py \
        --index benchmark/datasets/$idx \
        --target-root benchmark/datasets/$root \
        --backend codex --model $MODEL \
        --out benchmark/results/ai_pen_test_${MODEL}_${ds}.run$i.findings.json
    # if you hit a rate limit, wait for the window and re-run just the failed one
  done
done
```

Each envelope records `config: SASTAnalyzer(model=gpt-5.6-luna, backend=codex)` and
`dry_run: false` — that is your proof it ran on the subscription, not the mock.

## Step 2 — score + aggregate + drop into the README

Identical to `RUN_PAID_PASS.md` Step "Score each run, then aggregate", but with
`MODEL=gpt-5.6-luna` and `--tool "ai_pen_test:gpt-5.6-luna-codex"`. Fill the README's
ai-pen-test column with the file+CWE mean ± range from
`results/ai_pen_test_gpt-5.6-luna_*.aggregate.json`, label it
**"ai-pen-test (gpt-5.6-luna, via Codex sub)"**, and keep the honest read: expect it
ahead on semantic/business-logic CWEs, behind on deterministic-pattern CWEs, with
disclosed losses. Never replace a PENDING cell with anything that doesn't trace to a
real envelope.

## If the subscription route is more hassle than it's worth

The metered-API fallback is small: GPT-5.6 Luna via OpenRouter/OpenAI Batch API
(50% off) is ~$15–40 for the whole pass, fully comparable, no rate-limit juggling.
See `RUN_PAID_PASS.md`.
