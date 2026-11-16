"""Privacy-preserving survey protocol (Part 2 design, sections 2-3 and 3.1).

Roles
  respondent_submit : each respondent sends Enc(x_j) and Enc(x_j^2) for every question j
  AggregationServer : checks eligibility, uniqueness, shape and well-formedness;
                      multiplies ciphertexts mod n^2; releases once when N >= k
  Analyst           : decrypts the 2m totals, sanity-checks them, and computes
                      mean and variance per question

The server never decrypts. The analyst never sees a submission, only the totals.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction

from paillier import PrivateKey, PublicKey, decrypt, encrypt


@dataclass(frozen=True)
class SurveyParams:
    num_questions: int = 10
    answer_min: int = 1
    answer_max: int = 5
    k_threshold: int = 10

    @property
    def cipher_count(self) -> int:
        """Ciphertexts per submission: one for x and one for x^2 per question."""
        return 2 * self.num_questions


class SubmissionError(Exception):
    """A submission was rejected by the server's checks."""


class ReleaseError(Exception):
    """The server refused to release aggregates."""


class IntegrityWarning(Exception):
    """Decrypted totals fall outside the public plaintext bounds."""


def respondent_submit(pk: PublicKey, answers: list[int], params: SurveyParams) -> list[int]:
    """Encrypt one respondent's answers into 2m ciphertexts, ordered (c_1, d_1, c_2, d_2, ...)."""
    if len(answers) != params.num_questions:
        raise ValueError(f"expected {params.num_questions} answers, got {len(answers)}")
    if any(not params.answer_min <= x <= params.answer_max for x in answers):
        raise ValueError("answer outside the public range")
    out: list[int] = []
    for x in answers:
        out.append(encrypt(pk, x))       # c_ij = Enc(x_ij)
        out.append(encrypt(pk, x * x))   # d_ij = Enc(x_ij^2)
    return out


@dataclass(frozen=True)
class Release:
    """What the server sends the analyst: 2m aggregate ciphertexts and the respondent count N."""
    aggregates: tuple[int, ...]  # (C_1, D_1, ..., C_m, D_m)
    n_respondents: int


class AggregationServer:
    def __init__(self, pk: PublicKey, params: SurveyParams, eligible: set[str]):
        self.pk = pk
        self.params = params
        self.eligible = set(eligible)
        self._submissions: dict[str, tuple[int, ...]] = {}
        self._release: Release | None = None

    @property
    def count(self) -> int:
        return len(self._submissions)

    def accept(self, person_id: str, ciphertexts: list[int]) -> None:
        if self._release is not None:
            raise ReleaseError("survey is closed")
        if person_id not in self.eligible:
            raise SubmissionError("person is not on the eligibility list")
        if person_id in self._submissions:
            raise SubmissionError("duplicate submission")
        if len(ciphertexts) != self.params.cipher_count:
            raise SubmissionError("wrong number of ciphertexts")
        n_sq = self.pk.n_sq
        for c in ciphertexts:
            # Format check only: values must be units in Z*_{n^2}. Says nothing about the plaintext.
            if not 0 < c < n_sq or math.gcd(c, n_sq) != 1:
                raise SubmissionError("ciphertext is not a unit in Z*_{n^2}")
        self._submissions[person_id] = tuple(ciphertexts)

    def release(self) -> Release:
        """Return aggregates once N >= k. Repeat calls return the same object, never recompute."""
        if self._release is not None:
            return self._release
        if self.count < self.params.k_threshold:
            raise ReleaseError(
                f"only {self.count} submissions; threshold is {self.params.k_threshold}"
            )
        n_sq = self.pk.n_sq
        subs = list(self._submissions.values())
        totals = []
        for idx in range(self.params.cipher_count):
            acc = 1
            for sub in subs:
                acc = (acc * sub[idx]) % n_sq  # homomorphic addition
            totals.append(acc)
        self._release = Release(tuple(totals), self.count)
        return self._release


@dataclass(frozen=True)
class QuestionStats:
    sum_x: int
    sum_x2: int
    n: int

    @property
    def mean(self) -> Fraction:
        return Fraction(self.sum_x, self.n)

    @property
    def variance(self) -> Fraction:
        return Fraction(self.sum_x2, self.n) - self.mean**2


class Analyst:
    def __init__(self, pk: PublicKey, sk: PrivateKey, params: SurveyParams):
        if sk.public != pk:
            raise ValueError("private key does not match public key")
        self.pk, self.sk, self.params = pk, sk, params

    def decrypt_release(self, release: Release) -> list[QuestionStats]:
        n = release.n_respondents
        if n < self.params.k_threshold:
            raise ReleaseError("release below threshold")
        lo, hi = self.params.answer_min, self.params.answer_max
        stats = []
        for j in range(self.params.num_questions):
            s = decrypt(self.sk, release.aggregates[2 * j])
            q = decrypt(self.sk, release.aggregates[2 * j + 1])
            if not (0 <= s <= hi * n) or not (0 <= q <= hi * hi * n):
                # Public bounds on the plaintext sums. Signals bad input in aggregate, not who.
                raise IntegrityWarning(f"question {j + 1}: totals outside plaintext bounds")
            stats.append(QuestionStats(s, q, n))
        return stats


def plaintext_stats(answers: list[list[int]]) -> list[QuestionStats]:
    """Non-private baseline: the same statistics computed directly on plaintext answers."""
    n = len(answers)
    m = len(answers[0])
    out = []
    for j in range(m):
        col = [row[j] for row in answers]
        out.append(QuestionStats(sum(col), sum(x * x for x in col), n))
    return out
