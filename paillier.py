"""Pure-Python Paillier additively homomorphic encryption (standard library only).

Scheme (with generator g = n + 1):
  KeyGen : n = p*q, lam = lcm(p-1, q-1), mu = lam^{-1} mod n
  Enc(m) : c = (1 + m*n) * r^n mod n^2,   r random in Z_n^*
  Dec(c) : m = L(c^lam mod n^2) * mu mod n,  where L(x) = (x - 1) / n
  Add    : Dec(c1 * c2 mod n^2) = m1 + m2 mod n
  Scalar : Dec(c^k mod n^2)     = k * m mod n
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass


def _small_primes(limit: int = 1000) -> list[int]:
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    return [i for i, flag in enumerate(sieve) if flag]


_SMALL_PRIMES = _small_primes()


def is_probable_prime(candidate: int, rounds: int = 40) -> bool:
    """Trial division followed by Miller-Rabin with random bases."""
    if candidate < 2:
        return False
    for p in _SMALL_PRIMES:
        if candidate % p == 0:
            return candidate == p
    d, s = candidate - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(candidate - 3) + 2
        x = pow(a, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class PublicKey:
    n: int

    @property
    def n_sq(self) -> int:
        return self.n * self.n

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()


@dataclass(frozen=True)
class PrivateKey:
    public: PublicKey
    lam: int
    mu: int
    # Factors are kept so that other libraries (e.g. phe) can be given the same key.
    p: int | None = None
    q: int | None = None


def keypair_from_primes(p: int, q: int) -> tuple[PublicKey, PrivateKey]:
    """Build a key pair from known primes (used by tests and generate_keypair)."""
    if p == q:
        raise ValueError("p and q must differ")
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    if math.gcd(n, lam) != 1:
        raise ValueError("gcd(n, lambda) must be 1; choose different primes")
    pk = PublicKey(n)
    # With g = n + 1, L(g^lam mod n^2) = lam mod n, so mu = lam^{-1} mod n.
    mu = pow(lam, -1, n)
    return pk, PrivateKey(pk, lam, mu, p, q)


def generate_keypair(bits: int = 1024) -> tuple[PublicKey, PrivateKey]:
    """Generate a key pair whose modulus n has about `bits` bits."""
    if bits < 16 or bits % 2:
        raise ValueError("bits must be an even integer >= 16")
    half = bits // 2
    while True:
        p = _random_prime(half)
        q = _random_prime(half)
        if p != q and math.gcd(p * q, math.lcm(p - 1, q - 1)) == 1:
            return keypair_from_primes(p, q)


def _random_unit(n: int) -> int:
    while True:
        r = secrets.randbelow(n)
        if r > 0 and math.gcd(r, n) == 1:
            return r


def encrypt(pk: PublicKey, m: int, r: int | None = None) -> int:
    """Encrypt m in [0, n). Pass r only for deterministic tests."""
    if not 0 <= m < pk.n:
        raise ValueError("plaintext must lie in [0, n)")
    if r is None:
        r = _random_unit(pk.n)
    return ((1 + m * pk.n) * pow(r, pk.n, pk.n_sq)) % pk.n_sq


def decrypt(sk: PrivateKey, c: int) -> int:
    n = sk.public.n
    n_sq = sk.public.n_sq
    if not 0 < c < n_sq:
        raise ValueError("ciphertext must lie in (0, n^2)")
    u = pow(c, sk.lam, n_sq)
    return ((u - 1) // n) * sk.mu % n


def add(pk: PublicKey, c1: int, c2: int) -> int:
    """Ciphertext of m1 + m2 (mod n)."""
    return (c1 * c2) % pk.n_sq


def add_plain(pk: PublicKey, c: int, k: int) -> int:
    """Ciphertext of m + k (mod n), without fresh randomness."""
    return (c * (1 + pk.n * (k % pk.n))) % pk.n_sq


def mul_plain(pk: PublicKey, c: int, k: int) -> int:
    """Ciphertext of k * m (mod n)."""
    return pow(c, k % pk.n, pk.n_sq)


def encrypt_sum(pk: PublicKey, ciphertexts: list[int]) -> int:
    """Ciphertext of the sum of the underlying plaintexts (mod n)."""
    acc = encrypt(pk, 0, r=1)
    for c in ciphertexts:
        acc = add(pk, acc, c)
    return acc
