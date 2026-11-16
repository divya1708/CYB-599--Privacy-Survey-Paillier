"""Correctness tests for the Paillier implementation (stdlib unittest only)."""

import random
import unittest

from paillier import (
    add,
    add_plain,
    decrypt,
    encrypt,
    encrypt_sum,
    generate_keypair,
    keypair_from_primes,
    mul_plain,
)


class TestKnownAnswer(unittest.TestCase):
    """Hand-checkable toy example: p=11, q=13, n=143, lambda=60."""

    def setUp(self):
        self.pk, self.sk = keypair_from_primes(11, 13)

    def test_parameters(self):
        self.assertEqual(self.pk.n, 143)
        self.assertEqual(self.sk.lam, 60)
        self.assertEqual(self.sk.mu, pow(60, -1, 143))

    def test_fixed_randomness_roundtrip(self):
        c = encrypt(self.pk, 5, r=2)
        self.assertEqual(c, ((1 + 5 * 143) * pow(2, 143, 143 * 143)) % (143 * 143))
        self.assertEqual(decrypt(self.sk, c), 5)

    def test_all_plaintexts_roundtrip(self):
        for m in range(self.pk.n):
            with self.subTest(m=m):
                self.assertEqual(decrypt(self.sk, encrypt(self.pk, m)), m)


class TestRandomKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk, cls.sk = generate_keypair(256)

    def test_key_size(self):
        self.assertGreaterEqual(self.pk.bit_length, 255)

    def test_roundtrip_edge_values(self):
        for m in (0, 1, self.pk.n - 1):
            with self.subTest(m=m):
                self.assertEqual(decrypt(self.sk, encrypt(self.pk, m)), m)

    def test_roundtrip_random_values(self):
        rng = random.Random(1)
        for _ in range(50):
            m = rng.randrange(self.pk.n)
            self.assertEqual(decrypt(self.sk, encrypt(self.pk, m)), m)

    def test_encryption_is_probabilistic(self):
        self.assertNotEqual(encrypt(self.pk, 42), encrypt(self.pk, 42))

    def test_additive_homomorphism_with_wraparound(self):
        rng = random.Random(2)
        for _ in range(50):
            a, b = rng.randrange(self.pk.n), rng.randrange(self.pk.n)
            c = add(self.pk, encrypt(self.pk, a), encrypt(self.pk, b))
            self.assertEqual(decrypt(self.sk, c), (a + b) % self.pk.n)

    def test_add_plain(self):
        c = add_plain(self.pk, encrypt(self.pk, 100), 23)
        self.assertEqual(decrypt(self.sk, c), 123)

    def test_scalar_multiplication(self):
        c = mul_plain(self.pk, encrypt(self.pk, 7), 6)
        self.assertEqual(decrypt(self.sk, c), 42)

    def test_encrypted_sum_matches_plain_sum(self):
        values = [3, 1_000_000, 2**31 - 1, 0, 17]
        cts = [encrypt(self.pk, v) for v in values]
        self.assertEqual(decrypt(self.sk, encrypt_sum(self.pk, cts)), sum(values))

    def test_empty_sum_is_zero(self):
        self.assertEqual(decrypt(self.sk, encrypt_sum(self.pk, [])), 0)


class TestInputValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk, cls.sk = keypair_from_primes(11, 13)

    def test_plaintext_out_of_range(self):
        with self.assertRaises(ValueError):
            encrypt(self.pk, -1)
        with self.assertRaises(ValueError):
            encrypt(self.pk, self.pk.n)

    def test_ciphertext_out_of_range(self):
        with self.assertRaises(ValueError):
            decrypt(self.sk, 0)
        with self.assertRaises(ValueError):
            decrypt(self.sk, self.pk.n_sq)

    def test_bad_key_size(self):
        with self.assertRaises(ValueError):
            generate_keypair(15)
        with self.assertRaises(ValueError):
            generate_keypair(65)

    def test_equal_primes_rejected(self):
        with self.assertRaises(ValueError):
            keypair_from_primes(11, 11)


if __name__ == "__main__":
    unittest.main()
