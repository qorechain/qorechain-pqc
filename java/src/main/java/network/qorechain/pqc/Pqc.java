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
    public static final String VERSION = "0.2.0";

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

    /**
     * Deterministically derive {publicKey, secretKey} from the 32-byte FIPS-204
     * key-generation seed (ξ) — reproduces the shared {@code /vectors} and the
     * other language bindings byte-for-byte. As with {@link #mldsaKeygen}, the
     * returned secretKey is the seed itself.
     */
    public static byte[][] mldsaKeygenFromSeed(String level, byte[] seed) {
        MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(mldsaParams(level), seed);
        return new byte[][] {sk.getPublicKeyParameters().getEncoded(), sk.getSeed()};
    }

    /**
     * Sign {@code message} with {@code secretKey} (the 32-byte seed; empty context, FIPS-204 pure).
     *
     * <p>DETERMINISTIC (FIPS-204 §3.4): the same (secretKey, message) always yields
     * the same signature, matching every other language binding and the shared
     * {@code /vectors}. QoreChain's on-chain PQC verifier accepts ONLY deterministic
     * signatures, so this default is consensus-critical: do not change it. Use
     * {@link #mldsaSignHedged} for randomized signing in non-chain contexts.
     */
    public static byte[] mldsaSign(String level, byte[] secretKey, byte[] message) {
        MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(mldsaParams(level), secretKey);
        MLDSASigner signer = new MLDSASigner();
        // No ParametersWithRandom: Bouncy Castle then signs deterministically.
        signer.init(true, sk);
        signer.update(message, 0, message.length);
        try {
            return signer.generateSignature();
        } catch (org.bouncycastle.crypto.CryptoException e) {
            throw new IllegalStateException("ML-DSA signing failed", e);
        }
    }

    /**
     * Randomized (hedged) signing per FIPS-204 — NOT accepted by QoreChain's
     * on-chain verifier; opt-in for non-chain uses.
     */
    public static byte[] mldsaSignHedged(String level, byte[] secretKey, byte[] message) {
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

    // ── Hybrid sign-bytes ────────────────────────────────────────────────────
    // The message a PQC signature covers in QoreChain's hybrid-extension scheme,
    // where b0 is the tx body WITHOUT the PQC extension and auth the AuthInfo
    // bytes. Two forms exist and a network accepts exactly ONE at any height:
    //   v1 (legacy): BE32(len b0) || b0 || BE32(len auth) || auth
    //   v2:          "qorechain-pqc-hybrid-v2" || BE64(len chainId) || chainId || <v1 layout>
    // Networks that existed before chain release v3.1.98 verify v1 until that
    // upgrade is applied on them, v2 afterwards (signBytesVersionFor). This class
    // is pure: asking a network for its applied height is left to the caller.

    /** Domain tag of the v2 hybrid sign-bytes. */
    public static final String HYBRID_SIGN_BYTES_DOMAIN = "qorechain-pqc-hybrid-v2";
    /** Upgrade-plan name whose application switches a legacy network to v2. */
    public static final String SIGN_BYTES_V2_UPGRADE = "v3.1.98";
    /** Networks that verify v1 until {@link #SIGN_BYTES_V2_UPGRADE} is applied on them. */
    public static final java.util.List<String> LEGACY_SIGN_BYTES_CHAINS =
            java.util.List.of("qorechain-vladi", "qorechain-diana");
    /** Legacy sign-bytes form. */
    public static final int SIGN_BYTES_V1 = 1;
    /** Domain-tagged, chain-bound sign-bytes form. */
    public static final int SIGN_BYTES_V2 = 2;

    /**
     * The form a client must sign for {@code chainId}, given the height at which the
     * v3.1.98 plan was applied on it (0 = not applied). Mirror of the chain's
     * SignBytesVersionFor.
     */
    public static int signBytesVersionFor(String chainId, long v2AppliedHeight) {
        if (v2AppliedHeight > 0 || !LEGACY_SIGN_BYTES_CHAINS.contains(chainId)) return SIGN_BYTES_V2;
        return SIGN_BYTES_V1;
    }

    /** Legacy v1 sign-bytes: BE32(len(b0))||b0||BE32(len(auth))||auth. */
    public static byte[] hybridSignBytesV1(byte[] bodyWithoutPqcExt, byte[] authInfoBytes) {
        ByteBuffer buf = ByteBuffer.allocate(8 + bodyWithoutPqcExt.length + authInfoBytes.length);
        buf.putInt(bodyWithoutPqcExt.length).put(bodyWithoutPqcExt);
        buf.putInt(authInfoBytes.length).put(authInfoBytes);
        return buf.array();
    }

    /** v2 sign-bytes, byte-identical to the chain's x/pqc/types.HybridSignBytes. */
    public static byte[] hybridSignBytesV2(String chainId, byte[] bodyWithoutPqcExt, byte[] authInfoBytes) {
        byte[] domain = HYBRID_SIGN_BYTES_DOMAIN.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] cid = chainId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(domain.length + 8 + cid.length + 8
                + bodyWithoutPqcExt.length + authInfoBytes.length);
        buf.put(domain).putLong(cid.length).put(cid);
        buf.putInt(bodyWithoutPqcExt.length).put(bodyWithoutPqcExt);
        buf.putInt(authInfoBytes.length).put(authInfoBytes);
        return buf.array();
    }

    /**
     * Hybrid sign-bytes in the given form ({@link #SIGN_BYTES_V1} or
     * {@link #SIGN_BYTES_V2}). There is no implicit form.
     *
     * @throws IllegalArgumentException for any other version
     */
    public static byte[] hybridSignBytes(int version, String chainId, byte[] bodyWithoutPqcExt, byte[] authInfoBytes) {
        if (version == SIGN_BYTES_V1) return hybridSignBytesV1(bodyWithoutPqcExt, authInfoBytes);
        if (version == SIGN_BYTES_V2) return hybridSignBytesV2(chainId, bodyWithoutPqcExt, authInfoBytes);
        throw new IllegalArgumentException("hybrid sign-bytes version must be 1 or 2, got " + version);
    }
}
