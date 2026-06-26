package network.qorechain.pqc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Validates the Java/Bouncy Castle binding against the shared cross-language
 * vectors in ../vectors/flat.txt (generated from @noble, the FIPS reference).
 */
class VectorsTest {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static byte[] hex(String s) {
        if (s.equals("-")) return new byte[0]; // empty-message marker
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static Path vectorsFile() {
        for (String p : new String[] {"../vectors/flat.txt", "vectors/flat.txt"}) {
            Path candidate = Path.of(p);
            if (Files.exists(candidate)) return candidate;
        }
        throw new IllegalStateException("vectors/flat.txt not found");
    }

    @Test
    void sharedVectors() throws Exception {
        List<String> lines = Files.readAllLines(vectorsFile());
        int total = 0;
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.trim().split("\\s+");
            switch (f[0]) {
                case "mldsa":
                    assertTrue(Pqc.mldsaVerify(f[1], hex(f[2]), hex(f[3]), hex(f[4])),
                            f[1] + " vector must verify");
                    total++;
                    break;
                case "mlkem":
                    assertArrayEquals(hex(f[4]), Pqc.mlkemDecapsulate(f[1], hex(f[2]), hex(f[3])),
                            f[1] + " decaps mismatch");
                    total++;
                    break;
                case "shake":
                    byte[] msg = hex(f[1]);
                    assertArrayEquals(hex(f[2]), Pqc.shake256(msg, 32), "shake out32");
                    assertArrayEquals(hex(f[3]), Pqc.shake256(msg, 64), "shake out64");
                    total++;
                    break;
                default:
                    break;
            }
        }
        assertTrue(total >= 30, "expected the full vector set");
    }

    @Test
    void roundtripAndHelpers() {
        byte[][] kp = Pqc.mldsaKeygen("ml-dsa-87");
        byte[] sb = Pqc.hybridSignBytes(new byte[] {1, 2, 3}, new byte[] {9, 9});
        assertArrayEquals(new byte[] {0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9}, sb);
        byte[] sig = Pqc.mldsaSign("ml-dsa-87", kp[1], sb);
        assertTrue(Pqc.mldsaVerify("ml-dsa-87", kp[0], sb, sig));
        assertEquals(20, Pqc.pubkeyHash(kp[0], 20).length);

        byte[][] kem = Pqc.mlkemKeygen("ml-kem-1024");
        byte[][] enc = Pqc.mlkemEncapsulate("ml-kem-1024", kem[0]);
        assertArrayEquals(enc[1], Pqc.mlkemDecapsulate("ml-kem-1024", kem[1], enc[0]));
    }
}
