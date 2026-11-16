#!/usr/bin/env bash
# Reproduce everything from a clean checkout: venv, dependencies, tests, benchmark.
# Usage: ./run.sh          (full benchmark, roughly 20-30 minutes on a laptop)
#        ./run.sh --quick  (N = 10, 100 only; a few minutes)
set -euo pipefail
cd "$(dirname "$0")"

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet -r requirements.txt

export PYTHONPATH="$PWD"
echo "== unit and protocol tests =="
python -m unittest discover -s tests -v

echo "== benchmark =="
if [[ "${1:-}" == "--quick" ]]; then
  python -u benchmark.py --quick --out results
else
  python -u benchmark.py --out results
fi
echo "Results written to results.md and results.json"
