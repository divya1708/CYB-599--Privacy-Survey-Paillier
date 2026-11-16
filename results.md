# Benchmark results

Client cost is measured on a pool of real submissions; end-to-end client totals are estimated as per-submission time times N.

## Sizes and per-operation cost

| Nominal bits | Modulus n (bits) | Ciphertext (bytes) | Submission (bytes) | Client ms / submission | Encrypt ms (pure / phe) | Add ms (pure / phe) | Decrypt ms (pure / phe) |
|---|---|---|---|---|---|---|---|
| 2048 | 2048 | 512 | 10240 | 2103.1 | 105.88 / 102.91 | 0.0756 / 0.0506 | 107.28 / 29.02 |
| 3072 | 3072 | 768 | 15360 | 12698.1 | 320.36 / 313.89 | 0.1040 / 0.0984 | 321.70 / 90.49 |

## Protocol timings by N

| Nominal bits | N | Correct vs plaintext | Client total (s, est.) | Server accept (s) | Server release (s) | Analyst decrypt (s) | End-to-end (s, est.) | Plaintext baseline (ms) | Server storage (KB) |
|---|---|---|---|---|---|---|---|---|---|
| 2048 | 10 | yes | 21.03 | 0.010 | 0.011 | 2.066 | 23.12 | 0.018 | 100.0 |
| 2048 | 100 | yes | 210.31 | 0.098 | 0.100 | 2.111 | 212.62 | 0.147 | 1000.0 |
| 2048 | 1000 | yes | 2103.14 | 1.009 | 0.979 | 2.113 | 2107.24 | 0.680 | 10000.0 |
| 2048 | 10000 | yes | 21031.44 | 9.855 | 9.849 | 2.062 | 21053.20 | 6.981 | 100000.0 |
| 3072 | 10 | yes | 126.98 | 0.061 | 0.064 | 21.631 | 148.74 | 0.060 | 150.0 |
| 3072 | 100 | yes | 1269.81 | 0.590 | 0.665 | 21.608 | 1292.67 | 0.284 | 1500.0 |
| 3072 | 1000 | yes | 12698.12 | 6.264 | 6.731 | 21.645 | 12732.76 | 2.297 | 15000.0 |
| 3072 | 10000 | yes | 126981.17 | 63.343 | 30.642 | 6.514 | 127081.67 | 6.568 | 150000.0 |
