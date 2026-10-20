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
    public static final String VERSION = "0.2.3";

    private Pqc() {}

    // ── Input checking ───────────────────────────────────────────────────────
    // Every argument is checked for null and exact FIPS-204 / FIPS-203 length
    // BEFORE it reaches Bouncy Castle. mldsaVerify reports bad input as false;
    // every other method throws IllegalArgumentException naming the argument.

    /** ML-DSA secret-key size in this binding: the 32-byte FIPS-204 key-generation seed (xi). */
    public static final int MLDSA_SEED_LENGTH = 32;

    private static int mldsaPublicKeyLength(String level) {
        switch (level) {
            case "ml-dsa-44": return 1312;
            case "ml-dsa-65": return 1952;
            case "ml-dsa-87": return 2592;
            default: throw unknownLevel("ML-DSA", level);
        }
    }

    private static int mldsaSignatureLength(String level) {
        switch (level) {
            case "ml-dsa-44": return 2420;
            case "ml-dsa-65": return 3309;
            case "ml-dsa-87": return 4627;
            default: throw unknownLevel("ML-DSA", level);
        }
    }

    /** Size of the FIPS-204 EXPANDED secret key that the other bindings use. */
    private static int mldsaExpandedSecretKeyLength(String level) {
        switch (level) {
            case "ml-dsa-44": return 2560;
            case "ml-dsa-65": return 4032;
            case "ml-dsa-87": return 4896;
            default: throw unknownLevel("ML-DSA", level);
        }
    }

    private static int[] mlkemLengths(String level) { // {publicKey, secretKey, ciphertext}
        switch (level) {
            case "ml-kem-512": return new int[] {800, 1632, 768};
            case "ml-kem-768": return new int[] {1184, 2400, 1088};
            case "ml-kem-1024": return new int[] {1568, 3168, 1568};
            default: throw unknownLevel("ML-KEM", level);
        }
    }

    private static IllegalArgumentException unknownLevel(String family, String level) {
        return new IllegalArgumentException("unknown " + family + " level: " + level);
    }

    private static void requireLevel(String fn, String level) {
        if (level == null) throw new IllegalArgumentException(fn + ": level must not be null");
    }

    private static void requireNonNull(String fn, String arg, Object value) {
        if (value == null) throw new IllegalArgumentException(fn + ": " + arg + " must not be null");
    }

    private static void requireLength(String fn, String arg, byte[] value, int length) {
        requireNonNull(fn, arg, value);
        if (value.length != length) {
            throw new IllegalArgumentException(
                    fn + ": " + arg + " must be exactly " + length + " bytes, got " + value.length);
        }
    }

    /**
     * The ML-DSA secret key in this binding is the 32-byte FIPS-204 seed (xi),
     * NOT the expanded secret key the other bindings use. Bouncy Castle would
     * accept an expanded key here and silently use its first 32 bytes as the
     * seed; those bytes are rho, which is also the first 32 bytes of the PUBLIC
     * key, so the resulting key is one anyone can derive. Reject it loudly.
     */
    private static void requireMldsaSeed(String fn, String level, String arg, byte[] seed) {
        requireNonNull(fn, arg, seed);
        if (seed.length == MLDSA_SEED_LENGTH) return;
        if (seed.length == mldsaExpandedSecretKeyLength(level)) {
            throw new IllegalArgumentException(fn + ": " + arg + " is " + seed.length + " bytes, the "
                    + level + " EXPANDED secret key used by the JS/Go/Rust/Python/C bindings. This Java "
                    + "binding takes the 32-byte FIPS-204 key-generation seed (xi) instead. The first 32 "
                    + "bytes of an expanded key are rho, which is public (also the first 32 bytes of the "
                    + "public key), so they must never be used as a seed. Pass the 32-byte seed returned "
                    + "by mldsaKeygen / mldsaKeygenFromSeed.");
        }
        throw new IllegalArgumentException(fn + ": " + arg + " must be exactly " + MLDSA_SEED_LENGTH
                + " bytes (the FIPS-204 seed xi), got " + seed.length);
    }

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
     *
     * <p><b>This differs from every other binding</b>, whose secret key is the
     * expanded FIPS-204 key (4896 bytes for ML-DSA-87). The signing methods here
     * reject an expanded key with an {@link IllegalArgumentException}.
     *
     * @throws IllegalArgumentException if {@code level} is null or unknown
     */
    public static byte[][] mldsaKeygen(String level) {
        requireLevel("mldsaKeygen", level);
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
     *
     * @throws IllegalArgumentException if {@code level} is null or unknown, or
     *     {@code seed} is null or not exactly 32 bytes (an expanded secret key is
     *     rejected with an explanation)
     */
    public static byte[][] mldsaKeygenFromSeed(String level, byte[] seed) {
        requireLevel("mldsaKeygenFromSeed", level);
        requireMldsaSeed("mldsaKeygenFromSeed", level, "seed", seed);
        MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(mldsaParams(level), seed);
        return new byte[][] {sk.getPublicKeyParameters().getEncoded(), sk.getSeed()};
    }

    /**
     * Sign {@code message} with {@code secretKey} (the 32-byte seed; empty context, FIPS-204 pure).
     *
     * <p>DETERMINISTIC (FIPS-204 §3.4): the same (secretKey, message) always yields
     * the same signature, matching every other language binding and the shared
     * {@code /vectors}. QoreChain's on-chain PQC verifier accepts any valid FIPS-204
     * signature, hedged or deterministic. Use {@link #mldsaSignHedged} for
     * randomized signing, which the chain accepts equally.
     *
     * @throws IllegalArgumentException if {@code level} is null or unknown,
     *     {@code secretKey} is null or not exactly the 32-byte seed (an expanded
     *     secret key is rejected with an explanation), or {@code message} is null
     */
    public static byte[] mldsaSign(String level, byte[] secretKey, byte[] message) {
        requireLevel("mldsaSign", level);
        requireMldsaSeed("mldsaSign", level, "secretKey", secretKey);
        requireNonNull("mldsaSign", "message", message);
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
     * Randomized (hedged) signing per FIPS-204 — accepted by QoreChain's
     * on-chain verifier like {@link #mldsaSign}; not reproducible.
     *
     * @throws IllegalArgumentException under the same conditions as {@link #mldsaSign}
     */
    public static byte[] mldsaSignHedged(String level, byte[] secretKey, byte[] message) {
        requireLevel("mldsaSignHedged", level);
        requireMldsaSeed("mldsaSignHedged", level, "secretKey", secretKey);
        requireNonNull("mldsaSignHedged", "message", message);
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

    /**
     * Verify {@code signature} over {@code message} under {@code publicKey}.
     * Never throws: a null or unknown level, a null or wrong-length public key or
     * signature, a null message or any other malformed input returns false.
     */
    public static boolean mldsaVerify(String level, byte[] publicKey, byte[] message, byte[] signature) {
        if (level == null || publicKey == null || message == null || signature == null) return false;
        final MLDSAParameters params;
        try {
            params = mldsaParams(level);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (publicKey.length != mldsaPublicKeyLength(level)) return false;
        if (signature.length != mldsaSignatureLength(level)) return false;
        try {
            MLDSAPublicKeyParameters pk = new MLDSAPublicKeyParameters(params, publicKey);
            MLDSASigner signer = new MLDSASigner();
            signer.init(false, pk);
            signer.update(message, 0, message.length);
            return signer.verifySignature(signature);
        } catch (RuntimeException e) {
            return false;
        }
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

    /**
     * Generate an ML-KEM keypair. Returns {publicKey, secretKey}.
     *
     * @throws IllegalArgumentException if {@code level} is null or unknown
     */
    public static byte[][] mlkemKeygen(String level) {
        requireLevel("mlkemKeygen", level);
        MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
        g.init(new MLKEMKeyGenerationParameters(new SecureRandom(), mlkemParams(level)));
        AsymmetricCipherKeyPair kp = g.generateKeyPair();
        byte[] pk = ((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded();
        byte[] sk = ((MLKEMPrivateKeyParameters) kp.getPrivate()).getEncoded();
        return new byte[][] {pk, sk};
    }

    /**
     * Encapsulate to {@code publicKey}. Returns {ciphertext, sharedSecret}.
     *
     * @throws IllegalArgumentException if {@code level} is null or unknown, or
     *     {@code publicKey} is null or not exactly the level's public-key size
     */
    public static byte[][] mlkemEncapsulate(String level, byte[] publicKey) {
        requireLevel("mlkemEncapsulate", level);
        requireLength("mlkemEncapsulate", "publicKey", publicKey, mlkemLengths(level)[0]);
        MLKEMPublicKeyParameters pk = new MLKEMPublicKeyParameters(mlkemParams(level), publicKey);
        SecretWithEncapsulation enc = new MLKEMGenerator(new SecureRandom()).generateEncapsulated(pk);
        return new byte[][] {enc.getEncapsulation(), enc.getSecret()};
    }

    /**
     * Decapsulate {@code ciphertext} with {@code secretKey}. Returns the shared secret.
     *
     * @throws IllegalArgumentException if {@code level} is null or unknown, or
     *     {@code secretKey} / {@code ciphertext} is null or not exactly the
     *     level's size
     */
    public static byte[] mlkemDecapsulate(String level, byte[] secretKey, byte[] ciphertext) {
        requireLevel("mlkemDecapsulate", level);
        int[] len = mlkemLengths(level);
        requireLength("mlkemDecapsulate", "secretKey", secretKey, len[1]);
        requireLength("mlkemDecapsulate", "ciphertext", ciphertext, len[2]);
        MLKEMPrivateKeyParameters sk = new MLKEMPrivateKeyParameters(mlkemParams(level), secretKey);
        return new MLKEMExtractor(sk).extractSecret(ciphertext);
    }

    // ── SHAKE-256 (FIPS-202) + blockchain helpers ────────────────────────────

    /** SHAKE-256 digest of {@code data} with {@code outLen} bytes. */
    public static byte[] shake256(byte[] data, int outLen) {
        requireNonNull("shake256", "data", data);
        if (outLen < 0) throw new IllegalArgumentException("shake256: outLen must be >= 0, got " + outLen);
        SHAKEDigest d = new SHAKEDigest(256);
        d.update(data, 0, data.length);
        byte[] out = new byte[outLen];
        d.doFinal(out, 0, outLen);
        return out;
    }

    /** SHAKE-256(publicKey) truncated to {@code len} bytes (pay-to-pubkey-hash). */
    public static byte[] pubkeyHash(byte[] publicKey, int len) {
        requireNonNull("pubkeyHash", "publicKey", publicKey);
        if (len < 0) throw new IllegalArgumentException("pubkeyHash: len must be >= 0, got " + len);
        return shake256(publicKey, len);
    }

    // ── Hybrid sign-bytes ────────────────────────────────────────────────────
    // The message a PQC signature covers in QoreChain's hybrid-extension scheme,
    // where b0 is the tx body WITHOUT the PQC extension and auth the AuthInfo
    // bytes. Two forms exist and a network accepts exactly ONE at any height:
    //   v1 (legacy): BE32(len b0) || b0 || BE32(len auth) || auth
    //   v2:          "qorechain-pqc-hybrid-v2" || BE64(len chainId) || chainId || <v1 layout>
    // The two networks that existed before v2 (qorechain-vladi, qorechain-diana)
    // verify v1 until a switching upgrade is applied on them, v2 afterwards;
    // every other chain verifies v2 from genesis. The switch has shipped under
    // TWO plan names: testnet took it as "v3.1.98" and mainnet as "v3.2.0", and
    // each network keeps its record forever. Ask the network for every name in
    // SIGN_BYTES_V2_UPGRADES and pass the answers to signBytesVersionForApplied.
    // This class is pure: asking a network for its applied heights is left to
    // the caller.

    /** Domain tag of the v2 hybrid sign-bytes. */
    public static final String HYBRID_SIGN_BYTES_DOMAIN = "qorechain-pqc-hybrid-v2";
    /**
     * Every upgrade-plan name that switched a network to v2, newest first. Mirror
     * of the chain's {@code x/pqc/types.SignBytesV2Upgrades}. Any one of them
     * applied (height &gt; 0) means the network verifies v2.
     */
    public static final java.util.List<String> SIGN_BYTES_V2_UPGRADES =
            java.util.List.of("v3.2.0", "v3.1.98");
    /**
     * The primary (newest) name in {@link #SIGN_BYTES_V2_UPGRADES}.
     *
     * <p><b>Deprecated:</b> a network may have taken the switch under any name in
     * {@link #SIGN_BYTES_V2_UPGRADES} (testnet applied "v3.1.98", mainnet
     * "v3.2.0"), so querying only this one misreads testnet as not switched. Use
     * {@link #SIGN_BYTES_V2_UPGRADES} with {@link #signBytesVersionForApplied}.
     */
    public static final String SIGN_BYTES_V2_UPGRADE = "v3.2.0";
    /** Networks that verify v1 until one of {@link #SIGN_BYTES_V2_UPGRADES} is applied on them. */
    public static final java.util.List<String> LEGACY_SIGN_BYTES_CHAINS =
            java.util.List.of("qorechain-vladi", "qorechain-diana");
    /** Legacy sign-bytes form. */
    public static final int SIGN_BYTES_V1 = 1;
    /** Domain-tagged, chain-bound sign-bytes form. */
    public static final int SIGN_BYTES_V2 = 2;

    /**
     * The form a client must sign for {@code chainId}, given the height at which
     * the switch to v2 was applied on it (0 = not applied) — already the greatest
     * height across {@link #SIGN_BYTES_V2_UPGRADES}; prefer
     * {@link #signBytesVersionForApplied}, which computes it. Mirror of the
     * chain's SignBytesVersionFor.
     */
    public static int signBytesVersionFor(String chainId, long v2AppliedHeight) {
        if (v2AppliedHeight > 0 || !LEGACY_SIGN_BYTES_CHAINS.contains(chainId)) return SIGN_BYTES_V2;
        return SIGN_BYTES_V1;
    }

    /**
     * {@link #signBytesVersionFor} over every known upgrade name.
     * {@code appliedHeights} maps a plan name to the height at which the network
     * applied it (absent, null or 0 = not applied); the greatest height across
     * {@link #SIGN_BYTES_V2_UPGRADES} decides and other names are ignored. Mirror
     * of the chain's SignBytesVersionForApplied.
     */
    public static int signBytesVersionForApplied(String chainId, java.util.Map<String, Long> appliedHeights) {
        long best = 0;
        if (appliedHeights != null) {
            for (String name : SIGN_BYTES_V2_UPGRADES) {
                Long h = appliedHeights.get(name);
                if (h != null && h > best) best = h;
            }
        }
        return signBytesVersionFor(chainId, best);
    }

    /** Legacy v1 sign-bytes: BE32(len(b0))||b0||BE32(len(auth))||auth. */
    public static byte[] hybridSignBytesV1(byte[] bodyWithoutPqcExt, byte[] authInfoBytes) {
        requireNonNull("hybridSignBytesV1", "bodyWithoutPqcExt", bodyWithoutPqcExt);
        requireNonNull("hybridSignBytesV1", "authInfoBytes", authInfoBytes);
        ByteBuffer buf = ByteBuffer.allocate(8 + bodyWithoutPqcExt.length + authInfoBytes.length);
        buf.putInt(bodyWithoutPqcExt.length).put(bodyWithoutPqcExt);
        buf.putInt(authInfoBytes.length).put(authInfoBytes);
        return buf.array();
    }

    /**
     * v2 sign-bytes, byte-identical to the chain's x/pqc/types.HybridSignBytes.
     *
     * @throws IllegalArgumentException if {@code chainId} is null or empty (v2
     *     binds a signature to one network, and no network has an empty
     *     chain-id), or either byte array is null
     */
    public static byte[] hybridSignBytesV2(String chainId, byte[] bodyWithoutPqcExt, byte[] authInfoBytes) {
        if (chainId == null || chainId.isEmpty()) {
            throw new IllegalArgumentException("hybridSignBytesV2: chainId is required");
        }
        requireNonNull("hybridSignBytesV2", "bodyWithoutPqcExt", bodyWithoutPqcExt);
        requireNonNull("hybridSignBytesV2", "authInfoBytes", authInfoBytes);
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
     * @throws IllegalArgumentException for any other version, or for v2 with a
     *     null or empty {@code chainId}
     */
    public static byte[] hybridSignBytes(int version, String chainId, byte[] bodyWithoutPqcExt, byte[] authInfoBytes) {
        if (version == SIGN_BYTES_V1) return hybridSignBytesV1(bodyWithoutPqcExt, authInfoBytes);
        if (version == SIGN_BYTES_V2) return hybridSignBytesV2(chainId, bodyWithoutPqcExt, authInfoBytes);
        throw new IllegalArgumentException("hybrid sign-bytes version must be 1 or 2, got " + version);
    }
}
