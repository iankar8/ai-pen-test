#!/usr/bin/env bash
#
# fetch_datasets.sh — clone third-party ground-truth corpora for the ai-pen-test benchmark.
#
# Ground truth we did NOT author (credibility contract item #1):
#   - OWASP Benchmark (Java, synthetic) — seeded stratified subset used as the "synthetic corner".
#   - SecurityEval (Python, labeled-insecure) — recall-oriented corpus.
#
# Datasets are large and are NEVER committed. benchmark/datasets/ is gitignored.
# Shallow clones (--depth 1) to keep footprint small; we record the resolved commit
# hash of each clone so a skeptic can reproduce the exact dataset state.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATASETS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)/datasets"

mkdir -p "${DATASETS_DIR}"

clone_shallow() {
  local url="$1"
  local dest="$2"
  local target="${DATASETS_DIR}/${dest}"

  if [ -d "${target}/.git" ]; then
    echo "[skip] ${dest} already cloned at ${target}"
  else
    echo "[clone] ${url} -> ${target}"
    git clone --depth 1 "${url}" "${target}"
  fi

  local commit
  commit="$(git -C "${target}" rev-parse HEAD)"
  echo "[commit] ${dest} @ ${commit}"
}

echo "=== OWASP Benchmark (Java) ==="
clone_shallow "https://github.com/OWASP-Benchmark/BenchmarkJava" "BenchmarkJava"

echo
echo "=== SecurityEval (Python) ==="
clone_shallow "https://github.com/s2e-lab/SecurityEval" "SecurityEval"

echo
echo "Done. Datasets in ${DATASETS_DIR} (gitignored)."
