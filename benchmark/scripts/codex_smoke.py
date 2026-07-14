#!/usr/bin/env python3
"""
codex_smoke.py — verify the Codex-CLI backend works AND see its raw output shape,
BEFORE spending a subscription window on the full benchmark.

Why this exists: the engine's `_call_codex` shells `codex exec` and hands stdout to
the existing JSON parser. If `codex exec` wraps the answer (logs, banners, tool
traces) the parser may need a tweak. This runs ONE file both ways so you can see the
raw text and confirm findings parse out — a 1-scan check, not a 1,560-scan batch.

Usage (on a machine with `codex` installed + `codex login` done):
    python3 benchmark/scripts/codex_smoke.py --model gpt-5.6-luna
"""
import argparse, shutil, subprocess, sys, json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SAMPLE = REPO / "tests" / "fixtures" / "vulnerable_code.py"  # ships in the repo


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gpt-5.6-luna",
                    help="codex model id, e.g. gpt-5.6-luna / gpt-5.6-terra / gpt-5.6-sol")
    ap.add_argument("--file", default=str(SAMPLE), help="a source file to analyze")
    args = ap.parse_args()

    if not shutil.which("codex"):
        sys.exit("codex CLI not on PATH. Install it and run `codex login` (ChatGPT sign-in) first.")

    print(f"codex: {shutil.which('codex')}")
    try:
        v = subprocess.run(["codex", "--version"], capture_output=True, text=True, timeout=30)
        print(f"version: {v.stdout.strip() or v.stderr.strip()}")
    except Exception as e:
        print(f"version check failed: {e}")

    # 1) Raw shape: a trivial prompt, so you can SEE what codex exec emits.
    print("\n--- RAW codex exec output (trivial prompt) ---")
    raw = subprocess.run(
        ["codex", "exec", "-m", args.model, "--sandbox", "read-only",
         "--skip-git-repo-check", "Reply with exactly this JSON and nothing else: {\"ok\": true}"],
        capture_output=True, text=True, timeout=300,
    )
    print(f"exit={raw.returncode}")
    print("STDOUT:\n" + raw.stdout[:2000])
    if raw.stderr.strip():
        print("STDERR:\n" + raw.stderr[:1000])

    # 2) End-to-end: run the real engine with backend=codex on one file, confirm parse.
    print("\n--- engine backend=codex on one file ---")
    sys.path.insert(0, str(REPO))
    try:
        from handlers.sast_analyzer import SASTAnalyzer
        analyzer = SASTAnalyzer(model=args.model, backend="codex")
        findings = analyzer._analyze_file(args.file, None)
        print(f"parsed {len(findings)} findings from {Path(args.file).name}")
        for f in findings[:5]:
            print(f"  - {f.cwe} {f.severity} L{f.line} {f.id}")
        print("\nIf findings parsed, the full run in RUN_SUBSCRIPTION_PASS.md will work. "
              "If 0 findings but the raw output above clearly contains JSON, the parser "
              "needs to strip codex's wrapper — send that raw output and it's a quick fix.")
    except Exception as e:
        print(f"engine codex path raised: {e}")
        print("Share this + the RAW output above and it's a quick adapter fix.")


if __name__ == "__main__":
    main()
