package network.qorechain.pqc;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * QoreChain post-quantum cryptography (Bouncy Castle binding).
 *
 * <p>Standardized NIST primitives:
 * <ul>
 *   <li>ML-DSA (FIPS-204) signatures — levels 44 / 65 / 87 (default 87)</li>
 *   <li>ML-KEM (FIPS-203) key encapsulation — levels 512 / 768 / 1024 (default 1024)</li>
 *   <li>SHAKE-256 (FIPS-202) extendable-output hash</li>
 * </ul>
 *
 * The API mirrors the other language bindings in this repo and is validated
 * against the shared vectors in {@code /vectors}.
 */
public final class Pqc {
    public static final String VERSION = "0.1.0";

    private Pqc() {}

    // ── ML-DSA (FIPS-204) ────────────────────────────────────────────────────

    private static MLDSAParameters mldsaParams(String level) {
        switch (level) {
            case "ml-dsa-44": return MLDSAParameters.ml_dsa_44;
            case "ml-dsa-65": return MLDSAParameters.ml_dsa_65;
            case "ml-dsa-87": return MLDSAParameters.ml_dsa_87;
            default: throw new IllegalArgumentException("unknown ML-DSA level: " + level);
        }
    }

    /**
     * Generate an ML-DSA keypair. Returns {publicKey, secretKey} where secretKey
     * is the 32-byte FIPS-204 key-generation seed (ξ).
     *
     * <p>Bouncy Castle 1.79 represents an ML-DSA private key by its seed; the
     * expanded {@code getEncoded()} form does not round-trip through the
     * {@code (params, byte[])} constructor, so the seed is the portable secret
     * key here. Verification and the cross-language vectors are unaffected
     * (those exchange public keys and signatures, never private keys).
     */
    public static byte[][] mldsaKeygen(String level) {
        MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
        g.init(new MLDSAKeyGenerationParameters(new SecureRandom(), mldsaParams(level)));
        AsymmetricCipherKeyPair kp = g.generateKeyPair();
        byte[] pk = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
        byte[] sk = ((MLDSAPrivateKeyParameters) kp.getPrivate()).getSeed();
        return new byte[][] {pk, sk};
    }

    /** Sign {@code message} with {@code secretKey} (the 32-byte seed; empty context, FIPS-204 pure). */
    public static byte[] mldsaSign(String level, byte[] secretKey, byte[] message) {
        MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(mldsaParams(level), secretKey);
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, new ParametersWithRandom(sk, new SecureRandom()));
        signer.update(message, 0, message.length);
        try {
            return signer.generateSignature();
        } catch (org.bouncycastle.crypto.CryptoException e) {
            throw new IllegalStateException("ML-DSA signing failed", e);
        }
    }

    /** Verify {@code signature} over {@code message} under {@code publicKey}. */
    public static boolean mldsaVerify(String level, byte[] publicKey, byte[] message, byte[] signature) {
        MLDSAPublicKeyParameters pk = new MLDSAPublicKeyParameters(mldsaParams(level), publicKey);
        MLDSASigner signer = new MLDSASigner();
        signer.init(false, pk);
        signer.update(message, 0, message.length);
        return signer.verifySignature(signature);
    }

    // ── ML-KEM (FIPS-203) ────────────────────────────────────────────────────

    private static MLKEMParameters mlkemParams(String level) {
        switch (level) {
            case "ml-kem-512": return MLKEMParameters.ml_kem_512;
            case "ml-kem-768": return MLKEMParameters.ml_kem_768;
            case "ml-kem-1024": return MLKEMParameters.ml_kem_1024;
            default: throw new IllegalArgumentException("unknown ML-KEM level: " + level);
        }
    }

    /** Generate an ML-KEM keypair. Returns {publicKey, secretKey}. */
    public static byte[][] mlkemKeygen(String level) {
        MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
        g.init(new MLKEMKeyGenerationParameters(new SecureRandom(), mlkemParams(level)));
        AsymmetricCipherKeyPair kp = g.generateKeyPair();
        byte[] pk = ((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded();
        byte[] sk = ((MLKEMPrivateKeyParameters) kp.getPrivate()).getEncoded();
        return new byte[][] {pk, sk};
    }

    /** Encapsulate to {@code publicKey}. Returns {ciphertext, sharedSecret}. */
    public static byte[][] mlkemEncapsulate(String level, byte[] publicKey) {
        MLKEMPublicKeyParameters pk = new MLKEMPublicKeyParameters(mlkemParams(level), publicKey);
        SecretWithEncapsulation enc = new MLKEMGenerator(new SecureRandom()).generateEncapsulated(pk);
        return new byte[][] {enc.getEncapsulation(), enc.getSecret()};
    }

    /** Decapsulate {@code ciphertext} with {@code secretKey}. Returns the shared secret. */
    public static byte[] mlkemDecapsulate(String level, byte[] secretKey, byte[] ciphertext) {
        MLKEMPrivateKeyParameters sk = new MLKEMPrivateKeyParameters(mlkemParams(level), secretKey);
        return new MLKEMExtractor(sk).extractSecret(ciphertext);
    }

    // ── SHAKE-256 (FIPS-202) + blockchain helpers ────────────────────────────

    /** SHAKE-256 digest of {@code data} with {@code outLen} bytes. */
    public static byte[] shake256(byte[] data, int outLen) {
        SHAKEDigest d = new SHAKEDigest(256);
        d.update(data, 0, data.length);
        byte[] out = new byte[outLen];
        d.doFinal(out, 0, outLen);
        return out;
    }

    /** SHAKE-256(publicKey) truncated to {@code len} bytes (pay-to-pubkey-hash). */
    public static byte[] pubkeyHash(byte[] publicKey, int len) {
        return shake256(publicKey, len);
    }

    /** Canonical PQC sign-bytes: BE32(len(b0))||b0||BE32(len(auth))||auth. */
    public static byte[] hybridSignBytes(byte[] bodyWithoutPqcExt, byte[] authInfoBytes) {
        ByteBuffer buf = ByteBuffer.allocate(8 + bodyWithoutPqcExt.length + authInfoBytes.length);
        buf.putInt(bodyWithoutPqcExt.length).put(bodyWithoutPqcExt);
        buf.putInt(authInfoBytes.length).put(authInfoBytes);
        return buf.array();
    }
}
