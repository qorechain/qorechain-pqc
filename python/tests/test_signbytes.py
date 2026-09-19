"""Hybrid sign-bytes v1 (legacy) / v2 against the chain's v3.1.98 KAT vectors."""
import json, os, unittest
import qorpqc as pqc

with open(os.path.join(os.path.dirname(__file__), "..", "..", "vectors", "signbytes-kat-v3.1.98.json"), encoding="utf-8") as _f:
    KAT = json.load(_f)


class SignBytes(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(pqc.HYBRID_SIGN_BYTES_DOMAIN.decode(), KAT["hybrid_domain"])
        self.assertEqual(pqc.SIGN_BYTES_V2_UPGRADE, "v3.1.98")
        self.assertEqual(tuple(pqc.LEGACY_SIGN_BYTES_CHAINS), ("qorechain-vladi", "qorechain-diana"))

    def test_hybrid_v2_kat(self):
        self.assertEqual(len(KAT["hybrid_v2"]), 5)
        for v in KAT["hybrid_v2"]:
            b0, a = bytes.fromhex(v["body_without_pqc_ext_hex"]), bytes.fromhex(v["auth_info_hex"])
            self.assertEqual(pqc.hybrid_sign_bytes_v2(v["chain_id"], b0, a).hex(), v["sign_bytes_hex"], v["name"])
            self.assertEqual(pqc.hybrid_sign_bytes("v2", v["chain_id"], b0, a).hex(), v["sign_bytes_hex"], v["name"])

    def test_v1_layout_and_dispatch(self):
        want = bytes([0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9])
        self.assertEqual(pqc.hybrid_sign_bytes_v1(b"\x01\x02\x03", b"\x09\x09"), want)
        self.assertEqual(pqc.hybrid_sign_bytes("v1", "qorechain-vladi", b"\x01\x02\x03", b"\x09\x09"), want)
        with self.assertRaises(ValueError):
            pqc.hybrid_sign_bytes("auto", "qorechain-vladi", b"", b"")
        with self.assertRaises(ValueError):
            pqc.hybrid_sign_bytes_v2("", b"", b"")

    def test_version_truth_table(self):
        for c in ("qorechain-vladi", "qorechain-diana"):
            for h in (0, "0", None):
                self.assertEqual(pqc.sign_bytes_version_for(c, h), "v1")
            for h in (5746000, "5746000"):
                self.assertEqual(pqc.sign_bytes_version_for(c, h), "v2")
        self.assertEqual(pqc.sign_bytes_version_for("qorechain-other", 0), "v2")
        self.assertEqual(pqc.sign_bytes_version_for("qorechain-other", "5746000"), "v2")

    def test_v2_signature_does_not_verify_over_v1(self):
        pk, sk = pqc.mldsa.keygen()
        v2 = pqc.hybrid_sign_bytes("v2", "qorechain-vladi", b"\x01\x02\x03", b"\x09")
        v1 = pqc.hybrid_sign_bytes("v1", "qorechain-vladi", b"\x01\x02\x03", b"\x09")
        sig = pqc.mldsa.sign(sk, v2)
        self.assertTrue(pqc.mldsa.verify(pk, v2, sig))
        self.assertFalse(pqc.mldsa.verify(pk, v1, sig))


if __name__ == "__main__":
    unittest.main()
