"""Interoperability with python-paillier (phe): both implementations use g = n + 1, so ciphertexts should be mutually decryptable."""

import unittest

from paillier import add, decrypt, encrypt, keypair_from_primes

try:
    import phe
    from phe import paillier as phe_paillier
except ImportError:  # pragma: no cover
    phe = None


@unittest.skipIf(phe is None, "python-paillier (phe) is not installed; run: pip install phe")
class TestPheInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use the same primes on both sides so the keys are identical.
        p, q = 1000003, 1000033
        cls.pk, cls.sk = keypair_from_primes(p, q)
        cls.p_pk = phe_paillier.PaillierPublicKey(cls.pk.n)
        cls.p_sk = phe_paillier.PaillierPrivateKey(cls.p_pk, p, q)

    # phe encodes signed values and rejects anything above max_int = n // 3 - 1,
    # so the interop values stay below that bound.
    def _wrap(self, c):
        """phe decrypts EncryptedNumber objects, so wrap a raw ciphertext int."""
        return phe_paillier.EncryptedNumber(self.p_pk, c)

    def test_pure_encrypt_phe_decrypt(self):
        for m in (0, 1, 12345, 10**11):
            with self.subTest(m=m):
                self.assertEqual(self.p_sk.decrypt(self._wrap(encrypt(self.pk, m))), m)

    def test_phe_encrypt_pure_decrypt(self):
        for m in (0, 1, 12345, 10**11):
            with self.subTest(m=m):
                c = self.p_pk.encrypt(m).ciphertext(be_secure=False)
                self.assertEqual(decrypt(self.sk, c), m)

    def test_mixed_homomorphic_sum(self):
        c_pure = encrypt(self.pk, 1000)
        c_phe = self.p_pk.encrypt(2345).ciphertext(be_secure=False)
        self.assertEqual(decrypt(self.sk, add(self.pk, c_pure, c_phe)), 3345)
        # And the other direction: phe adds a pure-encrypted value.
        summed = self.p_pk.encrypt(5) + self._wrap(encrypt(self.pk, 7))
        self.assertEqual(self.p_sk.decrypt(summed), 12)


if __name__ == "__main__":
    unittest.main()
