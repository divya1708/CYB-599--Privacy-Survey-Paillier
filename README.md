# CYB 599 Part 3: Privacy-Preserving Survey Analytics with Paillier

Implementation and evaluation for the Part 2 design: an institution computes per-question sum, sum of squares, mean, and variance over encrypted survey answers. No party sees an individual answer in plaintext. Respondents encrypt `x` and `x²` for each of 10 questions (answers 1–5), the server multiplies ciphertexts without decrypting, and the analyst decrypts only the totals. The release is blocked below a threshold of 10 respondents and happens only once.

Security scope is semi-honest parties with no collusion between the server and the analyst. See `REPORT.md` for the full discussion.

## Contents

| File | Purpose |
|---|---|
| `paillier.py` | Pure-Python Paillier cryptosystem (standard library only): keygen, encrypt, decrypt, homomorphic add, scalar multiply |
| `survey.py` | Protocol roles: respondent submission, aggregation server (eligibility, uniqueness, shape, well-formedness, threshold, single release), analyst (decrypt, sanity bounds, mean, variance), plaintext baseline |
| `tests/test_paillier.py` | Known-answer test, round-trip for all plaintexts of a toy key, random-key properties, input validation |
| `tests/test_survey.py` | Mean and variance against plaintext, gating rules, integrity bound |
| `tests/test_phe_interop.py` | Ciphertexts from `paillier.py` decrypt under `phe` (python-paillier) and vice versa |
| `benchmark.py` | Timings, ciphertext and submission sizes, correctness against plaintext for each N, and a `phe` comparison |
| `run.sh` | Clean-environment run: venv, dependencies, tests, benchmark |
| `requirements.txt` | `phe` (interop and comparison), `tqdm` (progress bars) |
| `results.md`, `results.json` | Output of the full benchmark run reported in `REPORT.md` |

## Requirements

- Python 3.10 or newer (uses `int | None` annotations and `math.lcm`).
- Internet access for the first `pip install`.

No other dependencies are needed to run the protocol or the tests.

## Run

### macOS / Linux / Git Bash / WSL

```bash
./run.sh            # tests, then full benchmark (roughly 30-60 minutes)
./run.sh --quick    # tests, then benchmark with N = 10, 100 only
```

### Windows PowerShell

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH = (Get-Location).Path
python -m unittest discover -s tests -v
python -u benchmark.py --out results          # full run
python -u benchmark.py --quick --out results  # quick run
```

Expected output: 31 tests pass, then the benchmark prints progress bars and writes `results.md` and `results.json`.

## Parameter sets

| Nominal size | Modulus n | n² | Ciphertext | Submission (20 ciphertexts) | Role |
|---|---|---|---|---|---|
| 2048 | 2048 bits | 4096 bits | 512 B | 10,240 B | Benchmark comparison only (about 112-bit security) |
| 3072 | 3072 bits | 6144 bits | 768 B | 15,360 B | Design parameter (about 128-bit security) |

Primes are generated at `bits / 2` each. Keys use the standard `g = n + 1` simplification.

## Notes on the benchmark

- **Client cost** is measured on a pool of 50 real submissions per key size. For N above 50 the pool is cycled, and client time is scaled to N as per-submission time × N. Encrypting 10,000 submissions at 3072 bits in pure Python would take well over a day, so this is an estimate. The server costs (accept, release) and the analyst cost are measured at the full N.
- **Correctness** is checked for every N by comparing decrypted statistics with plaintext statistics computed on the same cycled answers. The benchmark raises an error on any mismatch.
- **`phe`** uses the same primes as our key. Its own key generation is slow in pure Python at these sizes, so it is not timed.

## Limitations

- Single-machine timings from one full run. Results vary with CPU load (the 3072-bit per-submission time differed between two runs).
- No zero-knowledge range proofs, so there are no proof-size measurements. Those are the Part 2 stretch goal.
- Input validity is not enforced by the respondent. The server checks only format, and the analyst's sanity bounds detect gross out-of-range totals but not who sent them.
- The server is semi-honest. A malicious server can drop, duplicate, or scale ciphertexts.
- No threshold decryption, so whoever holds `sk` can decrypt the totals.

## Reproducibility

Keys are random per run, so ciphertexts differ between runs. Correctness and the timing structure should reproduce. Exact timings will not.
