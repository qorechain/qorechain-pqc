import json, os, unittest
import qorechain_pqc as pqc

VDIR = os.path.join(os.path.dirname(__file__), "..", "..", "vectors")
def load(n): return json.load(open(os.path.join(VDIR, n)))
def hb(s): return bytes.fromhex(s)

class Vectors(unittest.TestCase):
    def test_mldsa(self):
        for lvl in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87"):
            s = pqc.MlDsa(lvl)
            for c in load(f"{lvl}.json")["cases"]:
                self.assertTrue(s.verify(hb(c["publicKey"]), hb(c["message"]), hb(c["signature"])), lvl)
    def test_mlkem(self):
        for lvl in ("ml-kem-512", "ml-kem-768", "ml-kem-1024"):
            k = pqc.MlKem(lvl)
            for c in load(f"{lvl}.json")["cases"]:
                self.assertEqual(k.decapsulate(hb(c["secretKey"]), hb(c["cipherText"])), hb(c["sharedSecret"]), lvl)
    def test_shake(self):
        for c in load("shake-256.json")["cases"]:
            m = hb(c["message"])
            self.assertEqual(pqc.shake256(m, 32).hex(), c["out32"])
            self.assertEqual(pqc.shake256(m, 64).hex(), c["out64"])
    def test_roundtrip(self):
        pk, sk = pqc.mldsa.keygen()
        sb = pqc.hybrid_sign_bytes(b"\x01\x02\x03", b"\x09\x09")
        self.assertEqual(sb, bytes([0,0,0,3,1,2,3,0,0,0,2,9,9]))
        self.assertTrue(pqc.mldsa.verify(pk, sb, pqc.mldsa.sign(sk, sb)))
        self.assertEqual(len(pqc.pubkey_hash(pk)), 20)
        ek, dk = pqc.mlkem.keygen(); ct, ss1 = pqc.mlkem.encapsulate(ek)
        self.assertEqual(pqc.mlkem.decapsulate(dk, ct), ss1)

if __name__ == "__main__":
    unittest.main()
