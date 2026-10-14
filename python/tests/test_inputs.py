"""Malformed inputs: verify returns False and never raises; sign / encapsulate /
decapsulate raise ValueError naming the argument and the expected length, and
nothing malformed reaches liboqs."""
import unittest

import qorpqc as pqc

MSG = b"qorechain"


class MlDsaInputs(unittest.TestCase):
    def test_lengths_table(self):
        self.assertEqual(pqc.MLDSA_LENGTHS["ml-dsa-87"], (2592, 4896, 4627))

    def test_verify_false_on_malformed(self):
        for level, (pk_len, sk_len, sig_len) in pqc.MLDSA_LENGTHS.items():
            with self.subTest(level=level):
                s = pqc.MlDsa(level)
                pk, sk = s.keygen()
                sig = s.sign(sk, MSG)
                self.assertTrue(s.verify(pk, MSG, sig))
                self.assertTrue(s.verify(bytearray(pk), memoryview(MSG), bytearray(sig)))
                bad = [
                    (pk[:-1], MSG, sig), (pk + b"\x00", MSG, sig), (b"", MSG, sig),
                    (pk, MSG, sig[:-1]), (pk, MSG, sig + b"\x00"), (pk, MSG, b""),
                    (pk + b"\x00" * 10000, MSG, sig), (pk, MSG, sig + b"\x00" * 10000),
                    (pk, "qorechain", sig), (pk, None, sig), (pk, 123, sig),
                    (None, MSG, sig), (pk.hex(), MSG, sig), (pk, MSG, None), (pk, MSG, sig.hex()),
                ]
                for args in bad:
                    self.assertIs(s.verify(*args), False)

    def test_sign_names_bad_argument(self):
        for level, (pk_len, sk_len, sig_len) in pqc.MLDSA_LENGTHS.items():
            with self.subTest(level=level):
                s = pqc.MlDsa(level)
                _, sk = s.keygen()
                for bad in (sk[:-1], sk + b"\x00", sk + b"\x00" * 10000, b"\x00" * 32):
                    with self.assertRaisesRegex(ValueError, rf"{level}\.sign: secret_key must be exactly {sk_len} bytes, got {len(bad)}"):
                        s.sign(bad, MSG)
                    with self.assertRaisesRegex(ValueError, "secret_key"):
                        s.sign(bad, MSG, hedged=True)
                with self.assertRaisesRegex(ValueError, rf"secret_key must be bytes of {sk_len} bytes, got NoneType"):
                    s.sign(None, MSG)
                with self.assertRaisesRegex(ValueError, "message must be bytes, got str"):
                    s.sign(sk, "qorechain")
                self.assertEqual(len(s.sign(bytearray(sk), bytearray(MSG))), sig_len)


class MlKemInputs(unittest.TestCase):
    def test_encapsulate_decapsulate_name_bad_argument(self):
        for level, (pk_len, sk_len, ct_len) in pqc.MLKEM_LENGTHS.items():
            with self.subTest(level=level):
                k = pqc.MlKem(level)
                pk, sk = k.keygen()
                for bad in (pk[:-1], pk + b"\x00", pk + b"\x00" * 10000):
                    with self.assertRaisesRegex(ValueError, rf"{level}\.encapsulate: public_key must be exactly {pk_len} bytes, got {len(bad)}"):
                        k.encapsulate(bad)
                with self.assertRaisesRegex(ValueError, "public_key must be bytes"):
                    k.encapsulate(None)
                ct, ss = k.encapsulate(pk)
                self.assertEqual(k.decapsulate(sk, ct), ss)
                for bad in (sk[:-1], sk + b"\x00", sk + b"\x00" * 10000):
                    with self.assertRaisesRegex(ValueError, rf"{level}\.decapsulate: secret_key must be exactly {sk_len} bytes, got {len(bad)}"):
                        k.decapsulate(bad, ct)
                for bad in (ct[:-1], ct + b"\x00", ct + b"\x00" * 10000):
                    with self.assertRaisesRegex(ValueError, rf"{level}\.decapsulate: ciphertext must be exactly {ct_len} bytes, got {len(bad)}"):
                        k.decapsulate(sk, bad)
                with self.assertRaisesRegex(ValueError, "ciphertext must be bytes"):
                    k.decapsulate(sk, ct.hex())


if __name__ == "__main__":
    unittest.main()
