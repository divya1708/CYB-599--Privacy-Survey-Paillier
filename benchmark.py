"""Benchmark harness: timings, ciphertext/submission sizes, correctness vs plaintext, and a phe comparison.

Usage:  python3 benchmark.py [--quick]

Method notes (also in README):
  * Client encryption is measured on a pool of P = 50 real submissions per key size.
    For N > 50 the pool is cycled, so server-side costs are measured at the full N while
    client-side encryption is not repeated N times in pure Python (which would take hours).
  * Correctness is checked for every N against the plaintext statistics of the same cycled answers.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import time
from pathlib import Path

import phe
from tqdm import tqdm

from paillier import add, decrypt, encrypt, generate_keypair
from survey import (
    Analyst,
    AggregationServer,
    SurveyParams,
    plaintext_stats,
    respondent_submit,
)

POOL_SIZE = 50


def timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    out = fn(*args, **kwargs)
    return out, time.perf_counter() - t0


def micro_ops(pk, sk, reps: int) -> dict:
    """Per-operation cost of the pure implementation, and of the phe library at the same key size."""
    msgs = [random.randrange(1, 6) for _ in range(reps)]
    cts, t_enc = timed(lambda: [encrypt(pk, m) for m in msgs])
    _, t_add = timed(lambda: [add(pk, cts[i], cts[(i + 1) % reps]) for i in range(reps)])
    _, t_dec = timed(lambda: [decrypt(sk, c) for c in cts])

    # phe (python-paillier) on the same key. Reusing our primes avoids phe's slow pure-Python keygen.
    p_pk = phe.PaillierPublicKey(pk.n)
    p_sk = phe.PaillierPrivateKey(p_pk, sk.p, sk.q)
    p_cts, p_t_enc = timed(lambda: [p_pk.encrypt(m) for m in msgs])
    _, p_t_add = timed(lambda: [p_cts[i] + p_cts[(i + 1) % reps] for i in range(reps)])
    _, p_t_dec = timed(lambda: [p_sk.decrypt(c) for c in p_cts])

    return {
        "pure": {
            "encrypt_ms": 1000 * t_enc / reps,
            "add_ms": 1000 * t_add / reps,
            "decrypt_ms": 1000 * t_dec / reps,
        },
        "phe": {
            "encrypt_ms": 1000 * p_t_enc / reps,
            "add_ms": 1000 * p_t_add / reps,
            "decrypt_ms": 1000 * p_t_dec / reps,
        },
    }


def run_param_set(bits: int, n_values: list[int], params: SurveyParams, micro_reps: int) -> dict:
    print(f"\n== parameter set: nominal {bits}-bit ==", flush=True)
    pk, sk = generate_keypair(bits)
    print(f"   modulus n: {pk.bit_length} bits; n^2: {pk.n_sq.bit_length()} bits", flush=True)

    ct_bytes = math.ceil(pk.n_sq.bit_length() / 8)
    sub_bytes = params.cipher_count * ct_bytes

    print("   micro-benchmarks ...", flush=True)
    micro = micro_ops(pk, sk, micro_reps)

    rng = random.Random(bits)
    pool_answers = [
        [rng.randint(params.answer_min, params.answer_max) for _ in range(params.num_questions)]
        for _ in range(POOL_SIZE)
    ]
    print(f"   client: encrypting pool of {POOL_SIZE} submissions ...", flush=True)
    pool_subs, t_pool = timed(
        lambda: [
            respondent_submit(pk, row, params)
            for row in tqdm(pool_answers, desc=f"{bits}-bit pool", unit="sub")
        ]
    )
    client_ms_per_submission = 1000 * t_pool / POOL_SIZE

    analyst = Analyst(pk, sk, params)
    rows_out = []
    for n in n_values:
        print(f"   N={n} ...", flush=True)
        answers = [pool_answers[i % POOL_SIZE] for i in range(n)]
        people = [f"p{i}" for i in range(n)]
        server = AggregationServer(pk, params, set(people))

        _, t_accept = timed(
            lambda: [
                server.accept(people[i], pool_subs[i % POOL_SIZE])
                for i in tqdm(range(n), desc=f"N={n} accept", unit="sub", leave=False)
            ]
        )
        release, t_release = timed(server.release)
        stats, t_decrypt = timed(analyst.decrypt_release, release)

        # Plaintext baseline on the same N answers (time over repeated runs to get a stable reading).
        reps = 20 if n <= 1000 else 3
        base_times = []
        for _ in range(reps):
            base, dt = timed(plaintext_stats, answers)
            base_times.append(dt)
        baseline_ms = 1000 * statistics.median(base_times)

        correct = stats == base
        if not correct:
            raise AssertionError(f"decrypted statistics differ from plaintext at N={n}")

        server_total = t_accept + t_release
        rows_out.append(
            {
                "N": n,
                "correct_vs_plaintext": correct,
                "client_total_s_est": (client_ms_per_submission / 1000) * n,
                "server_accept_s": t_accept,
                "server_release_s": t_release,
                "server_total_s": server_total,
                "analyst_decrypt_s": t_decrypt,
                "end_to_end_s_est": (client_ms_per_submission / 1000) * n + server_total + t_decrypt,
                "plaintext_baseline_ms": baseline_ms,
                "server_storage_bytes": n * sub_bytes,
            }
        )

    return {
        "nominal_bits": bits,
        "modulus_bits": pk.bit_length,
        "n_squared_bits": pk.n_sq.bit_length(),
        "ciphertext_bytes": ct_bytes,
        "submission_bytes": sub_bytes,
        "plaintext_submission_bytes": params.num_questions,  # one byte per answer in 1..5
        "client_ms_per_submission": client_ms_per_submission,
        "micro_ms": micro,
        "by_N": rows_out,
    }


def render_markdown(results: dict) -> str:
    lines = ["# Benchmark results", ""]
    lines.append(
        "Client cost is measured on a pool of real submissions; end-to-end client totals are "
        "estimated as per-submission time times N."
    )
    lines.append("")
    lines.append("## Sizes and per-operation cost")
    lines.append("")
    lines.append(
        "| Nominal bits | Modulus n (bits) | Ciphertext (bytes) | Submission (bytes) | "
        "Client ms / submission | Encrypt ms (pure / phe) | Add ms (pure / phe) | Decrypt ms (pure / phe) |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in results["parameter_sets"]:
        m = r["micro_ms"]
        lines.append(
            f"| {r['nominal_bits']} | {r['modulus_bits']} | {r['ciphertext_bytes']} | "
            f"{r['submission_bytes']} | {r['client_ms_per_submission']:.1f} | "
            f"{m['pure']['encrypt_ms']:.2f} / {m['phe']['encrypt_ms']:.2f} | "
            f"{m['pure']['add_ms']:.4f} / {m['phe']['add_ms']:.4f} | "
            f"{m['pure']['decrypt_ms']:.2f} / {m['phe']['decrypt_ms']:.2f} |"
        )
    lines.append("")
    lines.append("## Protocol timings by N")
    lines.append("")
    lines.append(
        "| Nominal bits | N | Correct vs plaintext | Client total (s, est.) | Server accept (s) | "
        "Server release (s) | Analyst decrypt (s) | End-to-end (s, est.) | Plaintext baseline (ms) | "
        "Server storage (KB) |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in results["parameter_sets"]:
        for row in r["by_N"]:
            lines.append(
                f"| {r['nominal_bits']} | {row['N']} | {'yes' if row['correct_vs_plaintext'] else 'NO'} | "
                f"{row['client_total_s_est']:.2f} | {row['server_accept_s']:.3f} | "
                f"{row['server_release_s']:.3f} | {row['analyst_decrypt_s']:.3f} | "
                f"{row['end_to_end_s_est']:.2f} | {row['plaintext_baseline_ms']:.3f} | "
                f"{row['server_storage_bytes'] / 1024:.1f} |"
            )
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="smaller N and fewer micro reps")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    params = SurveyParams(num_questions=10, k_threshold=10)
    n_values = [10, 100] if args.quick else [10, 100, 1000, 10000]
    micro_reps = 10 if args.quick else 40

    sets = []
    for bits in (2048, 3072):  # 3072 = design parameter; 2048 = benchmark comparison only
        sets.append(run_param_set(bits, n_values, params, micro_reps))

    results = {
        "parameter_sets": sets,
        "survey": {"questions": params.num_questions, "k_threshold": params.k_threshold,
                   "answers": "1..5", "pool_size": POOL_SIZE},
        "notes": [
            "2048 is benchmark-only (about 112-bit security); 3072 is the design parameter (about 128-bit).",
            "Client encryption is timed on a pool of real submissions and scaled to N.",
            "Pool submissions are cycled for N > pool size; correctness is checked against the same cycled answers.",
        ],
    }
    out = Path(args.out)
    out.with_suffix(".json").write_text(json.dumps(results, indent=2))
    out.with_suffix(".md").write_text(render_markdown(results))
    print(f"\nwrote {out.with_suffix('.json')} and {out.with_suffix('.md')}")


if __name__ == "__main__":
    main()
