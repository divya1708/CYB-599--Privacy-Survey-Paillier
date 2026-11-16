# CYB 599 Part 3: Implementation and Evaluation of Privacy-Preserving Survey Analytics

## 1. Summary

This report evaluates a pure-Python implementation of the Part 2 design: Paillier additively homomorphic encryption applied to survey aggregation. The implementation passes 31 correctness tests, including interoperability with the `phe` library. In a full benchmark run, the decrypted sums, sums of squares, means, and variances matched a plaintext baseline for every respondent count tested (N = 10, 100, 1,000, and 10,000) at both parameter sets.

Performance does not meet the Part 2 budgets at the design parameter. At 3072 bits, one respondent's submission (20 encryptions) took about 12.7 s, against a budget of ≤ 2 s. The analyst's decryption took 6.5–21.6 s, against a budget of < 1 s. The server cost stays within seconds to minutes even at N = 10,000. Client encryption is the bottleneck, which matches the design's assumption that the respondent's device dominates cost.

## 2. System Under Test

The implementation has three layers:

- **`paillier.py`** implements Paillier with generator `g = n + 1`. Keys are generated from two random primes with Miller–Rabin testing. Encryption uses `c = (1 + m·n) · rⁿ mod n²` with fresh randomness from `secrets`. Decryption uses `m = L(cᵏ mod n²) · μ mod n`. Only the standard library is used.
- **`survey.py`** implements the three roles in Part 2. The respondent encrypts `xⱼ` and `xⱼ²` for each of m = 10 questions. The server checks eligibility, uniqueness, shape (exactly 2m = 20 ciphertexts), and well-formedness (each value a unit in ℤ*ₙ²). It multiplies ciphertexts per position and releases once when N ≥ k = 10. The analyst decrypts the 2m totals, checks the public bounds 0 ≤ Sⱼ ≤ 5N and 0 ≤ Qⱼ ≤ 25N, and computes exact rational mean and variance.
- **`benchmark.py`** measures timings and sizes, checks correctness at each N, and runs the same operations through `phe` (python-paillier) on the same key.

## 3. Correctness Testing

Thirty-one tests run from a clean environment using only `unittest`:

| Area | What is checked |
|---|---|
| Paillier core | A hand-computed toy key (p = 11, q = 13, n = 143) with a fixed randomness value; round-trip for every plaintext in the toy key; round-trip for 0, 1, n − 1, and 50 random values on a 256-bit key; probabilistic encryption; homomorphic addition with wraparound; plaintext addition and scalar multiplication; encrypted sums including the empty sum; input range checks |
| Protocol statistics | Mean and variance from encrypted totals equal the plaintext baseline on 12 random respondents; a small example with known sums, sums of squares, and zero variance |
| Gating | Release blocked below N = k; release returns the same object on repeat calls; no submissions accepted after release; duplicate and ineligible submissions rejected; wrong ciphertext count and non-unit ciphertexts rejected; honest client refuses out-of-range answers |
| Integrity bound | A cheating respondent submitting Enc(1000) is detected by the analyst's sanity bound, but the protocol cannot identify who sent it |
| Interoperability | Ciphertexts from `paillier.py` decrypt under `phe`, ciphertexts from `phe` decrypt under `paillier.py`, and a mixed-implementation sum decrypts correctly |

All 31 tests passed. The full benchmark run also verified exact equality with the plaintext statistics at every N.

## 4. Performance Measurements

The full run used two parameter sets. Times are from one full run on a single Windows laptop; background load on that machine was not controlled. Client costs are per submission (20 ciphertexts) or estimated for N respondents from the per-submission time.

### 4.1 Sizes and per-operation cost

| Parameter set | Modulus n | Ciphertext | Submission | Client per submission | Encrypt (pure / phe) | Add (pure / phe) | Decrypt (pure / phe) |
|---|---|---|---|---|---|---|---|
| 2048 (benchmark only) | 2048 bits | 512 B | 10,240 B | 2.10 s | 105.9 / 102.9 ms | 0.076 / 0.051 ms | 107.3 / 29.0 ms |
| 3072 (design) | 3072 bits | 768 B | 15,360 B | 12.70 s | 320.4 / 313.9 ms | 0.104 / 0.098 ms | 321.7 / 90.5 ms |

Ciphertext sizes match the design: 768 B per ciphertext and 15,360 B per submission at 3072 bits. Plaintext answers would fit in 10 bytes per submission, so the encrypted submission is about 1,500 times larger. Homomorphic addition is cheap, at about 0.1 ms per operation, so the server's aggregation cost is small relative to encryption.

### 4.2 Protocol timings by respondent count

**2048 bits (benchmark only)**

| N | Client total (est.) | Server accept + release | Analyst decrypt | End-to-end (est.) | Plaintext baseline | Server storage | Correct |
|---|---|---|---|---|---|---|---|
| 10 | 21.0 s | 0.021 s | 2.07 s | 23.1 s | 0.018 ms | 0.10 MB | yes |
| 100 | 210.3 s | 0.198 s | 2.11 s | 212.6 s | 0.147 ms | 1.0 MB | yes |
| 1,000 | 2,103 s (35 min) | 1.99 s | 2.11 s | 2,107 s | 0.680 ms | 10.2 MB | yes |
| 10,000 | 21,031 s (5.8 h) | 19.7 s | 2.06 s | 21,053 s | 6.98 ms | 102.4 MB | yes |

**3072 bits (design parameter)**

| N | Client total (est.) | Server accept + release | Analyst decrypt | End-to-end (est.) | Plaintext baseline | Server storage | Correct |
|---|---|---|---|---|---|---|---|
| 10 | 127.0 s | 0.125 s | 21.6 s | 148.7 s | 0.060 ms | 0.15 MB | yes |
| 100 | 1,270 s (21 min) | 1.25 s | 21.6 s | 1,293 s | 0.284 ms | 1.5 MB | yes |
| 1,000 | 12,698 s (3.5 h) | 13.0 s | 21.6 s | 12,733 s | 2.30 ms | 15.4 MB | yes |
| 10,000 | 126,981 s (35.3 h) | 94.0 s | 6.5 s | 127,082 s | 6.57 ms | 153.6 MB | yes |

### 4.3 Comparison with the Part 2 budgets

| Quantity | Part 2 budget | 2048 measured | 3072 measured | Verdict at 3072 |
|---|---|---|---|---|
| Client encryption per submission | ≤ 2 s | 2.10 s | 12.70 s | Fails (about 6× over) |
| Bandwidth per submission | ≈ 15 KB | 10 KB | 15 KB | Meets |
| Server aggregation, N = 10⁴ | Seconds | 19.7 s | 94.0 s | Fails in the strict sense (about a minute and a half) |
| Server storage, N = 10⁴ | ≈ 150 MB | 102 MB | 154 MB | Meets |
| Analyst decryption | < 1 s | 2.1 s | 6.5–21.6 s | Fails |
| Correctness | Exact match | Exact | Exact | Meets |

### 4.4 Interpreting the timings

**Client cost dominates.** Encryption is about 320 ms per ciphertext at 3072 bits, so a 20-value submission is the largest cost in the system. The spec's ≤ 2 s target assumed tens of milliseconds per encryption. Measured costs are several times higher, and the design's fallback of gmpy2 (faster modular arithmetic) is the most likely way to meet the budget. We did not test it.

**Two client measurements disagree.** The per-submission time at 3072 bits was 12.7 s in the full run and 8.2 s in an earlier quick run. Twenty micro-benchmark encryptions at 320 ms each predict about 6.4 s. The pool measurement is roughly twice that prediction. Sustained load on the laptop is the most likely cause, so the 3072-bit client figure should be read as a range of about 6–13 s rather than one number.

**Analyst decryption timing varies.** At 3072 bits, decryption took 21.6 s at N = 10, 100, and 1,000 but 6.5 s at N = 10,000, although the decryption work is the same. The 2048-bit numbers are stable at about 2.1 s. The 6.5 s figure matches the 20 × 320 ms prediction, so the 21.6 s readings look like run-time interference. A repeated measurement would confirm this.

**Server cost is linear in N.** Accept and release costs at 3072 bits grew from 0.13 s at N = 10 to 94 s at N = 10,000, which is close to linear. Each release multiplies 20 ciphertext columns over N submissions, and the accept step checks gcd on each ciphertext. Both stay far below client cost, consistent with the cost model in Part 2 §6.1.

**Plaintext baseline.** The same statistics on plaintext take 6.6 ms at N = 10,000, against 94 s for the server path at 3072 bits. The overhead is about 14,000×. Most of it comes from encryption, which the baseline does not perform.

**`phe` comparison.** The `phe` library encrypts at about the same speed as our implementation (314 ms vs 320 ms at 3072 bits). Its decryption is about 3.5× faster (90 ms vs 322 ms), likely because it uses CRT with the factors, which our decryption does not. Adding ciphertexts is at the same speed for both libraries. The interop tests show the two implementations are compatible.

## 5. Limitations and Discussion

**Scope of the security argument.** The design guarantees confidentiality against semi-honest parties, under the assumption that the server and analyst do not collude. It does not guarantee that every submitted value is in range. A malicious respondent who submits Enc(1000) skews the totals, and the analyst sees only that the bound was exceeded. Closing this gap needs zero-knowledge range proofs (the Part 2 stretch goal), which would add proof sizes to the evaluation. We did not implement them, so no proof-size measurements are reported.

**Malleability.** Anyone holding a Paillier ciphertext can scale or shift it. A malicious server could drop, duplicate, or scale submissions without detection. Verifiable aggregation would address this, and it is future work.

**Differencing and small groups.** The threshold k = 10 blocks release for small N, and the single-release rule blocks differencing across releases. Colluding respondents with the analyst can still recover the last answer in a group.

**Performance at the design parameter.** Pure Python misses the Part 2 budgets at 3072 bits on client encryption and analyst decryption. The honest conclusion is that a pure-Python prototype is acceptable for correctness and cost modelling, but not for interactive respondent devices. A production system would need native arithmetic (gmpy2 or a C library) and probably a batched encryption path.

**Benchmark method.** Client cost for N > 50 is estimated, not measured end to end, because pure-Python encryption at 3072 bits makes 10,000 real submissions infeasible on one machine. The pool is cycled, which keeps the server path honest (every accept and release runs at full N) but means the server sees repeated ciphertexts. Repeated values do not change arithmetic cost. Timings come from a single run on one machine.

**Key sizes.** The 2048-bit set is a comparison only and offers about 112-bit security. The 3072-bit set is the design parameter. The security level is an analogy to NIST's factoring-based mapping, not a tight bound on the decisional composite residuosity problem.

## 6. Conclusion

The implementation is correct: all 31 tests pass, and decrypted statistics match plaintext at every respondent count tested. The Part 2 design works end to end, and the server path scales linearly. It does not meet the performance budgets at 3072 bits. Client encryption (about 6–13 s per submission against a ≤ 2 s target) and analyst decryption (6.5–21.6 s against < 1 s) are the main gaps. Future work is a native-arithmetic backend, the zero-knowledge range proof stretch goal, and verifiable aggregation.

## Reproduction

See `README.md` for run instructions, parameter sets, and the benchmark method. The run that produced the numbers above is in `results.md` and `results.json`.
