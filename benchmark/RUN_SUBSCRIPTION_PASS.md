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
- **VERIFIED WORKING on this machine (2026-07-09):** engine `backend=codex` +
  `gpt-5.6-luna` analyzed `tests/fixtures/vulnerable_code.py` via the subscription and
  parsed **24 correctly-tagged findings** (CWE-328/89/79/78/22). No wrapper/parse issue.
  `_call_codex` uses `--ignore-user-config --ephemeral -s read-only -o <file>`.
- **Note:** repairing the backend required reinstalling the Codex CLI (it was broken,
  missing its native binary) — your codex is now **0.144.3** (was 0.130.0).
- **`--ignore-user-config` is load-bearing, not optional:** without it your Codex hooks
  fire on every call — injecting your command-center context into each SAST prompt
  (benchmark contamination) and burning ~18k tokens/call. It's baked into `_call_codex`.

## Step 0 — confirm environment (quick)

```bash
export PATH=/Users/iankar/.nvm/versions/node/v22.22.0/bin:$PATH   # codex lives here
codex --version        # expect codex-cli 0.144.3+; already signed in (tokens present)

# Optional re-confirm (one scan): proves the backend + your current auth/rate state
PY=/Users/iankar/ai-pen-test/.venv/bin/python
$PY benchmark/scripts/codex_smoke.py --model gpt-5.6-luna
```

## Step 1 — the overnight run (backend=codex, Luna, 1 run, ~190-file subset)

Reality of the codex-agent path: ~100s/file (each `codex exec` cold-starts the agent
and loads ~129 runtime skills — the irreducible ~6.6k-token floor even with
`--disable plugins`, which is baked in). So the full 521-file corpus is ~15h. This
runs a **seeded ~190-file subset (~5.3h) as ONE run** — an *indicative* GPT-5.6-Luna
column, labeled as such (1 run = no variance number; subset = fewer per-CWE samples).

The runner **checkpoints after every file and is failure-isolated**: if a call rate-
limits or the machine sleeps, re-run the exact same command and it resumes, skipping
completed files. So this is safe to `nohup` and leave overnight.

Kick it off before bed:

```bash
export PATH=/Users/iankar/.nvm/versions/node/v22.22.0/bin:$PATH   # codex lives here
PY=/Users/iankar/ai-pen-test/.venv/bin/python
cd /Users/iankar/ai-pen-test
$PY benchmark/scripts/build_overnight_subset.py    # writes the ~190-file indexes

nohup bash -c '
export PATH=/Users/iankar/.nvm/versions/node/v22.22.0/bin:$PATH
PY=/Users/iankar/ai-pen-test/.venv/bin/python
cd /Users/iankar/ai-pen-test
for ds in securityeval owasp; do
  idx=$([ $ds = securityeval ] && echo securityeval_overnight.json || echo owasp_overnight.json)
  root=$([ $ds = securityeval ] && echo SecurityEval || echo BenchmarkJava)
  $PY benchmark/runners/ai_pen_test_runner.py \
      --index benchmark/datasets/$idx --target-root benchmark/datasets/$root \
      --backend codex --model gpt-5.6-luna \
      --out benchmark/results/ai_pen_test_gpt-5.6-luna_${ds}.overnight.findings.json
done
' > benchmark/results/overnight.log 2>&1 &
echo "started pid $! — watch: tail -f benchmark/results/overnight.log"
```

Progress: `tail -f benchmark/results/overnight.log` shows `[i/N] file: K findings (Ns)`
per file. If it dies, rerun the whole `nohup …` block — it resumes from the checkpoint.
Each envelope records `config: SASTAnalyzer(model=gpt-5.6-luna, backend=codex)` and
`dry_run: false` — proof it ran on the subscription, not the mock. (For the full
3-run / full-corpus version later, use `*_index.json` / `owasp_subset.json` and loop
`run1/2/3` — but expect ~15h/run.)

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
