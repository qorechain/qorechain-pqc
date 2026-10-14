package network.qorechain.pqc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Malformed inputs: mldsaVerify returns false and never throws; every other
 * method throws IllegalArgumentException naming the argument. In particular the
 * ML-DSA secret key here is the 32-byte seed, and an expanded secret key (whose
 * first 32 bytes are the public rho) must be rejected, never used as a seed.
 */
class InputsTest {

    private static final byte[] MSG = "qorechain".getBytes(StandardCharsets.UTF_8);
    private static final String[][] MLDSA = {
        // level, publicKey, signature, expanded secret key
        {"ml-dsa-44", "1312", "2420", "2560"},
        {"ml-dsa-65", "1952", "3309", "4032"},
        {"ml-dsa-87", "2592", "4627", "4896"},
    };

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static String message(Runnable r) {
        return assertThrows(IllegalArgumentException.class, r::run).getMessage();
    }

    @Test
    void seedOfExactly32BytesIsRequired() {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 5);
        byte[][] kp = Pqc.mldsaKeygenFromSeed("ml-dsa-87", seed);
        assertArrayEquals(seed, kp[1]);
        for (int n : new int[] {0, 31, 33, 64}) {
            byte[] bad = new byte[n];
            String m = message(() -> Pqc.mldsaKeygenFromSeed("ml-dsa-87", bad));
            assertTrue(m.contains("seed") && m.contains("exactly 32 bytes") && m.contains("got " + n), m);
            m = message(() -> Pqc.mldsaSign("ml-dsa-87", bad, MSG));
            assertTrue(m.contains("mldsaSign: secretKey") && m.contains("exactly 32 bytes") && m.contains("got " + n), m);
            m = message(() -> Pqc.mldsaSignHedged("ml-dsa-87", bad, MSG));
            assertTrue(m.contains("mldsaSignHedged: secretKey") && m.contains("got " + n), m);
        }
        assertTrue(message(() -> Pqc.mldsaKeygenFromSeed("ml-dsa-87", null)).contains("seed must not be null"));
        assertTrue(message(() -> Pqc.mldsaSign("ml-dsa-87", null, MSG)).contains("secretKey must not be null"));
        assertTrue(message(() -> Pqc.mldsaSign("ml-dsa-87", seed, null)).contains("message must not be null"));
        assertTrue(message(() -> Pqc.mldsaSignHedged("ml-dsa-87", seed, null)).contains("message must not be null"));
    }

    @Test
    void expandedSecretKeyIsRejectedWithAnExplanation() {
        for (String[] l : MLDSA) {
            int expanded = Integer.parseInt(l[3]);
            byte[][] kp = Pqc.mldsaKeygen(l[0]);
            // An expanded key starts with rho, which is public: build one whose
            // first 32 bytes are exactly the public key's first 32 bytes.
            byte[] fake = new byte[expanded];
            System.arraycopy(kp[0], 0, fake, 0, 32);
            for (Runnable r : new Runnable[] {
                () -> Pqc.mldsaSign(l[0], fake, MSG),
                () -> Pqc.mldsaSignHedged(l[0], fake, MSG),
                () -> Pqc.mldsaKeygenFromSeed(l[0], fake),
            }) {
                String m = message(r);
                assertTrue(m.contains(expanded + " bytes") && m.contains("EXPANDED")
                        && m.contains("32-byte") && m.contains("rho"), m);
            }
        }
    }

    @Test
    void mldsaVerifyReturnsFalseOnMalformedInput() {
        for (String[] l : MLDSA) {
            String level = l[0];
            byte[][] kp = Pqc.mldsaKeygen(level);
            byte[] sig = Pqc.mldsaSign(level, kp[1], MSG);
            assertTrue(Pqc.mldsaVerify(level, kp[0], MSG, sig));
            byte[] pk = kp[0];
            Object[][] bad = {
                {level, Arrays.copyOf(pk, pk.length - 1), MSG, sig},
                {level, Arrays.copyOf(pk, pk.length + 1), MSG, sig},
                {level, new byte[0], MSG, sig},
                {level, pk, MSG, Arrays.copyOf(sig, sig.length - 1)},
                {level, pk, MSG, Arrays.copyOf(sig, sig.length + 1)},
                {level, pk, MSG, new byte[0]},
                {level, null, MSG, sig},
                {level, pk, null, sig},
                {level, pk, MSG, null},
                {null, pk, MSG, sig},
                {"ml-dsa-99", pk, MSG, sig},
            };
            for (Object[] b : bad) {
                assertFalse(Pqc.mldsaVerify((String) b[0], (byte[]) b[1], (byte[]) b[2], (byte[]) b[3]));
            }
        }
    }

    @Test
    void levelArgumentIsChecked() {
        assertTrue(message(() -> Pqc.mldsaKeygen(null)).contains("level must not be null"));
        assertTrue(message(() -> Pqc.mldsaKeygen("ml-dsa-99")).contains("unknown ML-DSA level"));
        assertTrue(message(() -> Pqc.mlkemKeygen(null)).contains("level must not be null"));
        assertTrue(message(() -> Pqc.mlkemKeygen("ml-kem-99")).contains("unknown ML-KEM level"));
        assertTrue(message(() -> Pqc.mldsaSign(null, new byte[32], MSG)).contains("level must not be null"));
        assertTrue(message(() -> Pqc.mlkemEncapsulate(null, new byte[1568])).contains("level must not be null"));
    }

    @Test
    void mlkemLengthsAreExact() {
        String[][] kem = {
            {"ml-kem-512", "800", "1632", "768"},
            {"ml-kem-768", "1184", "2400", "1088"},
            {"ml-kem-1024", "1568", "3168", "1568"},
        };
        for (String[] l : kem) {
            String level = l[0];
            int pkLen = Integer.parseInt(l[1]), skLen = Integer.parseInt(l[2]), ctLen = Integer.parseInt(l[3]);
            byte[][] kp = Pqc.mlkemKeygen(level);
            assertEquals(pkLen, kp[0].length);
            assertEquals(skLen, kp[1].length);
            byte[][] enc = Pqc.mlkemEncapsulate(level, kp[0]);
            assertArrayEquals(enc[1], Pqc.mlkemDecapsulate(level, kp[1], enc[0]));

            String m = message(() -> Pqc.mlkemEncapsulate(level, Arrays.copyOf(kp[0], pkLen - 1)));
            assertTrue(m.contains("mlkemEncapsulate: publicKey must be exactly " + pkLen + " bytes, got " + (pkLen - 1)), m);
            m = message(() -> Pqc.mlkemEncapsulate(level, Arrays.copyOf(kp[0], pkLen + 1)));
            assertTrue(m.contains("got " + (pkLen + 1)), m);
            assertTrue(message(() -> Pqc.mlkemEncapsulate(level, null)).contains("publicKey must not be null"));

            m = message(() -> Pqc.mlkemDecapsulate(level, Arrays.copyOf(kp[1], skLen - 1), enc[0]));
            assertTrue(m.contains("mlkemDecapsulate: secretKey must be exactly " + skLen + " bytes"), m);
            m = message(() -> Pqc.mlkemDecapsulate(level, kp[1], Arrays.copyOf(enc[0], ctLen + 1)));
            assertTrue(m.contains("mlkemDecapsulate: ciphertext must be exactly " + ctLen + " bytes"), m);
            assertTrue(message(() -> Pqc.mlkemDecapsulate(level, null, enc[0])).contains("secretKey must not be null"));
            assertTrue(message(() -> Pqc.mlkemDecapsulate(level, kp[1], null)).contains("ciphertext must not be null"));
        }
    }

    @Test
    void helpersRejectNull() {
        assertTrue(message(() -> Pqc.shake256(null, 32)).contains("data must not be null"));
        assertTrue(message(() -> Pqc.shake256(MSG, -1)).contains("outLen"));
        assertTrue(message(() -> Pqc.pubkeyHash(null, 20)).contains("publicKey must not be null"));
        assertTrue(message(() -> Pqc.hybridSignBytesV1(null, new byte[0])).contains("bodyWithoutPqcExt"));
        assertTrue(message(() -> Pqc.hybridSignBytesV2("qorechain-vladi", new byte[0], null)).contains("authInfoBytes"));
    }
}
