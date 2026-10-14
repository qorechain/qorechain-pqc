package network.qorechain.pqc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Hybrid sign-bytes v1 (legacy) / v2 against the chain's v3.1.98 KAT vectors. */
class SignBytesTest {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static byte[] hex(String s) {
        if (s.equals("-")) return new byte[0];
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static Path katFile() {
        for (String p : new String[] {"../vectors/signbytes-kat-v3.1.98.flat.txt", "vectors/signbytes-kat-v3.1.98.flat.txt"}) {
            Path candidate = Path.of(p);
            if (Files.exists(candidate)) return candidate;
        }
        throw new IllegalStateException("vectors/signbytes-kat-v3.1.98.flat.txt not found");
    }

    @Test
    void hybridV2Kat() throws Exception {
        int n = 0;
        for (String line : Files.readAllLines(katFile())) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.trim().split("\\s+");
            if (!f[0].equals("hybrid_v2")) continue;
            String chainId = new String(hex(f[2]), StandardCharsets.UTF_8);
            byte[] b0 = hex(f[3]), auth = hex(f[4]), want = hex(f[5]);
            assertArrayEquals(want, Pqc.hybridSignBytesV2(chainId, b0, auth), f[1]);
            assertArrayEquals(want, Pqc.hybridSignBytes(Pqc.SIGN_BYTES_V2, chainId, b0, auth), f[1]);
            n++;
        }
        assertEquals(5, n);
    }

    @Test
    void v1LayoutAndDispatch() {
        byte[] want = {0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9};
        assertArrayEquals(want, Pqc.hybridSignBytesV1(new byte[] {1, 2, 3}, new byte[] {9, 9}));
        assertArrayEquals(want, Pqc.hybridSignBytes(Pqc.SIGN_BYTES_V1, "qorechain-vladi", new byte[] {1, 2, 3}, new byte[] {9, 9}));
        assertThrows(IllegalArgumentException.class, () -> Pqc.hybridSignBytes(3, "qorechain-vladi", new byte[0], new byte[0]));
    }

    @Test
    void versionTruthTable() {
        for (String c : new String[] {"qorechain-vladi", "qorechain-diana"}) {
            assertEquals(Pqc.SIGN_BYTES_V1, Pqc.signBytesVersionFor(c, 0));
            assertEquals(Pqc.SIGN_BYTES_V2, Pqc.signBytesVersionFor(c, 5746000));
        }
        assertEquals(Pqc.SIGN_BYTES_V2, Pqc.signBytesVersionFor("qorechain-other", 0));
        assertEquals(Pqc.SIGN_BYTES_V2, Pqc.signBytesVersionFor("qorechain-other", 5746000));
    }

    @Test
    void upgradeNames() {
        assertEquals(java.util.List.of("v3.2.0", "v3.1.98"), Pqc.SIGN_BYTES_V2_UPGRADES);
        assertEquals("v3.2.0", Pqc.SIGN_BYTES_V2_UPGRADE);
    }

    @Test
    void versionForAppliedTruthTable() {
        for (String c : new String[] {"qorechain-vladi", "qorechain-diana"}) {
            // only v3.2.0 applied -> v2
            assertEquals(Pqc.SIGN_BYTES_V2, Pqc.signBytesVersionForApplied(c, java.util.Map.of("v3.2.0", 2981742L)));
            assertEquals(Pqc.SIGN_BYTES_V2, Pqc.signBytesVersionForApplied(c, java.util.Map.of("v3.2.0", 2981742L, "v3.1.98", 0L)));
            // only v3.1.98 applied -> v2
            assertEquals(Pqc.SIGN_BYTES_V2, Pqc.signBytesVersionForApplied(c, java.util.Map.of("v3.1.98", 5746000L)));
            // neither -> v1 on the legacy networks
            assertEquals(Pqc.SIGN_BYTES_V1, Pqc.signBytesVersionForApplied(c, java.util.Map.of("v3.2.0", 0L, "v3.1.98", 0L)));
            assertEquals(Pqc.SIGN_BYTES_V1, Pqc.signBytesVersionForApplied(c, java.util.Map.of()));
            assertEquals(Pqc.SIGN_BYTES_V1, Pqc.signBytesVersionForApplied(c, null));
            assertEquals(Pqc.SIGN_BYTES_V1, Pqc.signBytesVersionForApplied(c, java.util.Map.of("v9.9.9", 100L)));
        }
        // neither -> v2 elsewhere
        assertEquals(Pqc.SIGN_BYTES_V2, Pqc.signBytesVersionForApplied("qorechain-other", java.util.Map.of()));
        assertEquals(Pqc.SIGN_BYTES_V2, Pqc.signBytesVersionForApplied("qorechain-other", java.util.Map.of("v3.2.0", 1L)));
    }

    @Test
    void v2RefusesEmptyChainId() {
        assertThrows(IllegalArgumentException.class, () -> Pqc.hybridSignBytesV2("", new byte[] {1}, new byte[] {2}));
        assertThrows(IllegalArgumentException.class, () -> Pqc.hybridSignBytesV2(null, new byte[] {1}, new byte[] {2}));
        assertThrows(IllegalArgumentException.class, () -> Pqc.hybridSignBytes(Pqc.SIGN_BYTES_V2, "", new byte[] {1}, new byte[] {2}));
        assertArrayEquals(new byte[] {0, 0, 0, 1, 1, 0, 0, 0, 1, 2},
                Pqc.hybridSignBytes(Pqc.SIGN_BYTES_V1, "", new byte[] {1}, new byte[] {2}));
    }

    @Test
    void v2SignatureDoesNotVerifyOverV1() {
        byte[][] kp = Pqc.mldsaKeygen("ml-dsa-87");
        byte[] v2 = Pqc.hybridSignBytesV2("qorechain-vladi", new byte[] {1, 2, 3}, new byte[] {9});
        byte[] v1 = Pqc.hybridSignBytesV1(new byte[] {1, 2, 3}, new byte[] {9});
        byte[] sig = Pqc.mldsaSign("ml-dsa-87", kp[1], v2);
        assertTrue(Pqc.mldsaVerify("ml-dsa-87", kp[0], v2, sig));
        assertFalse(Pqc.mldsaVerify("ml-dsa-87", kp[0], v1, sig));
    }
}
