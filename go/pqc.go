// Package pqc provides QoreChain post-quantum cryptography.
//
// Standardized NIST primitives, wrapping Cloudflare CIRCL + x/crypto:
//   - ML-DSA   (FIPS-204) signatures — levels 44 / 65 / 87 (default 87)
//   - ML-KEM   (FIPS-203) key encapsulation — levels 512 / 768 / 1024 (default 1024)
//   - SHAKE-256 (FIPS-202) extendable-output hash
//
// The API mirrors the other language bindings in this repo and is validated
// against the shared vectors in /vectors.
package pqc

import (
	"encoding/binary"
	"errors"
	"fmt"

	mldsa44 "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	mldsa87 "github.com/cloudflare/circl/sign/mldsa/mldsa87"

	mlkem1024 "github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	mlkem512 "github.com/cloudflare/circl/kem/mlkem/mlkem512"
	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/sign"
	"golang.org/x/crypto/sha3"
)

const Version = "0.2.1"

// SigScheme is a unified ML-DSA signature scheme handle.
type SigScheme struct {
	Name string
	s    sign.Scheme
}

// KemScheme is a unified ML-KEM key-encapsulation scheme handle.
type KemScheme struct {
	Name string
	s    kem.Scheme
}

// ML-DSA (FIPS-204) levels.
var (
	MLDSA44 = SigScheme{"ml-dsa-44", mldsa44.Scheme()}
	MLDSA65 = SigScheme{"ml-dsa-65", mldsa65.Scheme()}
	MLDSA87 = SigScheme{"ml-dsa-87", mldsa87.Scheme()}
	// MLDSA is the QoreChain default (security level 5).
	MLDSA = MLDSA87
)

// ML-KEM (FIPS-203) levels.
var (
	MLKEM512  = KemScheme{"ml-kem-512", mlkem512.Scheme()}
	MLKEM768  = KemScheme{"ml-kem-768", mlkem768.Scheme()}
	MLKEM1024 = KemScheme{"ml-kem-1024", mlkem1024.Scheme()}
	// MLKEM is the QoreChain default (security level 5).
	MLKEM = MLKEM1024
)

// Keygen returns (publicKey, secretKey) for the scheme.
func (sc SigScheme) Keygen() (pub, sec []byte, err error) {
	pk, sk, err := sc.s.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	sec, _ = sk.MarshalBinary()
	return pub, sec, nil
}

// KeygenFromSeed deterministically derives (publicKey, secretKey) from the
// 32-byte FIPS-204 xi seed — reproduces the shared /vectors and the other
// language bindings byte-for-byte.
func (sc SigScheme) KeygenFromSeed(seed []byte) (pub, sec []byte, err error) {
	if len(seed) != sc.s.SeedSize() {
		return nil, nil, errors.New("pqc: bad seed length")
	}
	pk, sk := sc.s.DeriveKey(seed)
	pub, _ = pk.MarshalBinary()
	sec, _ = sk.MarshalBinary()
	return pub, sec, nil
}

// Sign signs message with secretKey (empty context, FIPS-204 pure).
// DETERMINISTIC (FIPS-204 section 3.4): same (secretKey, message) always yields
// the same signature — required by QoreChain's on-chain PQC verifier, and how
// the shared /vectors are generated.
func (sc SigScheme) Sign(secretKey, message []byte) ([]byte, error) {
	sk, err := sc.s.UnmarshalBinaryPrivateKey(secretKey)
	if err != nil {
		return nil, err
	}
	return sc.s.Sign(sk, message, nil), nil
}

// Verify checks signature over message under publicKey.
//
// The signature must be exactly the scheme's signature size. CIRCL's ML-DSA
// verifier reads the bytes it needs and ignores anything after them, so a
// 4,628-byte ML-DSA-87 signature (one trailing byte) verified here while the
// chain's FIPS-204 verifier, and every other binding, rejects it. A verifier
// that accepts more encodings than the chain lets a client believe a
// transaction is valid when the network will refuse it.
func (sc SigScheme) Verify(publicKey, message, signature []byte) bool {
	if len(signature) != sc.s.SignatureSize() {
		return false
	}
	pk, err := sc.s.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return false
	}
	return sc.s.Verify(pk, message, signature, nil)
}

// Keygen returns (publicKey, secretKey).
func (kc KemScheme) Keygen() (pub, sec []byte, err error) {
	pk, sk, err := kc.s.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	sec, _ = sk.MarshalBinary()
	return pub, sec, nil
}

// Encapsulate to publicKey returns (ciphertext, sharedSecret).
func (kc KemScheme) Encapsulate(publicKey []byte) (ct, ss []byte, err error) {
	pk, err := kc.s.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	return kc.s.Encapsulate(pk)
}

// Decapsulate ciphertext with secretKey returns the shared secret.
func (kc KemScheme) Decapsulate(secretKey, ciphertext []byte) ([]byte, error) {
	sk, err := kc.s.UnmarshalBinaryPrivateKey(secretKey)
	if err != nil {
		return nil, err
	}
	return kc.s.Decapsulate(sk, ciphertext)
}

// Shake256 returns a SHAKE-256 (FIPS-202) digest of data with outLen bytes.
func Shake256(data []byte, outLen int) []byte {
	out := make([]byte, outLen)
	h := sha3.NewShake256()
	h.Write(data)
	h.Read(out)
	return out
}

// PubkeyHash returns SHAKE-256(publicKey) truncated to len bytes (default 20).
func PubkeyHash(publicKey []byte, length int) []byte { return Shake256(publicKey, length) }

// Hybrid sign-bytes: the message a PQC signature covers in QoreChain's
// hybrid-extension scheme, where b0 is the tx body WITHOUT the PQC extension and
// auth is the AuthInfo bytes. Two forms exist and a network accepts exactly ONE of
// them at any height:
//
//	v1 (legacy): BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth
//	v2:          "qorechain-pqc-hybrid-v2" ‖ BE64(len chainID) ‖ chainID ‖
//	               BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth
//
// The two networks that existed before v2 (qorechain-vladi, qorechain-diana)
// verify v1 until a switching upgrade is applied on them, v2 afterwards; every
// other chain verifies v2 from genesis. The switch has shipped under TWO plan
// names: testnet took it as "v3.1.98" and mainnet as "v3.2.0", and each network
// keeps its record forever. Ask the network for every name in
// SignBytesV2Upgrades and pass the answers to SignBytesVersionForApplied. This
// package is pure: asking a network for its applied heights is left to the caller.

// HybridSignBytesDomain tags the v2 hybrid sign-bytes so a signature the same key
// produced in another context cannot be valid transaction sign-bytes.
const HybridSignBytesDomain = "qorechain-pqc-hybrid-v2"

// SignBytesV2Upgrades lists every upgrade-plan name that switched a network to
// v2, newest first. Mirror of the chain's x/pqc/types.SignBytesV2Upgrades. Any
// one of them applied (height > 0) means the network verifies v2.
var SignBytesV2Upgrades = []string{"v3.2.0", "v3.1.98"}

// SignBytesV2Upgrade is the primary (newest) plan name in SignBytesV2Upgrades.
//
// Deprecated: a network may have taken the switch under any name in
// SignBytesV2Upgrades (testnet applied "v3.1.98", mainnet "v3.2.0"). Querying
// only this name misreads testnet as not switched. Use SignBytesV2Upgrades and
// SignBytesVersionForApplied.
const SignBytesV2Upgrade = "v3.2.0"

// Sign-bytes form identifiers (match the chain's SignBytesVersionFor).
const (
	SignBytesV1 = 1
	SignBytesV2 = 2
)

// LegacySignBytesChains are the networks that verify v1 until one of
// SignBytesV2Upgrades is applied on them.
var LegacySignBytesChains = []string{"qorechain-vladi", "qorechain-diana"}

// SignBytesVersionFor returns SignBytesV2 if v2AppliedHeight > 0 or chainID is not
// a legacy network, otherwise SignBytesV1. Mirror of the chain's function.
// v2AppliedHeight must already be the greatest applied height across
// SignBytesV2Upgrades; prefer SignBytesVersionForApplied, which computes it.
func SignBytesVersionFor(chainID string, v2AppliedHeight int64) int {
	if v2AppliedHeight > 0 {
		return SignBytesV2
	}
	for _, c := range LegacySignBytesChains {
		if c == chainID {
			return SignBytesV1
		}
	}
	return SignBytesV2
}

// SignBytesVersionForApplied is SignBytesVersionFor over every known upgrade
// name: appliedHeights maps a plan name to the height at which the network
// applied it (absent or 0 = not applied), and the greatest height across
// SignBytesV2Upgrades decides. Names not in SignBytesV2Upgrades are ignored.
// Mirror of the chain's SignBytesVersionForApplied.
func SignBytesVersionForApplied(chainID string, appliedHeights map[string]int64) int {
	var best int64
	for _, name := range SignBytesV2Upgrades {
		if h := appliedHeights[name]; h > best {
			best = h
		}
	}
	return SignBytesVersionFor(chainID, best)
}

// HybridSignBytesV1 is the legacy form, byte-identical to the chain's
// x/pqc/types.HybridSignBytesLegacy.
func HybridSignBytesV1(bodyWithoutPqcExt, authInfoBytes []byte) []byte {
	out := make([]byte, 0, 8+len(bodyWithoutPqcExt)+len(authInfoBytes))
	out = binary.BigEndian.AppendUint32(out, uint32(len(bodyWithoutPqcExt)))
	out = append(out, bodyWithoutPqcExt...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(authInfoBytes)))
	out = append(out, authInfoBytes...)
	return out
}

// HybridSignBytesV2 is the v2 form, byte-identical to the chain's
// x/pqc/types.HybridSignBytes.
//
// chainID must not be empty: v2 sign-bytes exist to bind a signature to one
// network, and no network has an empty chain-id. An empty chainID is a caller
// bug and panics; HybridSignBytes returns it as an error instead.
func HybridSignBytesV2(chainID string, bodyWithoutPqcExt, authInfoBytes []byte) []byte {
	if chainID == "" {
		panic(errEmptyChainID)
	}
	out := make([]byte, 0, len(HybridSignBytesDomain)+8+len(chainID)+8+len(bodyWithoutPqcExt)+len(authInfoBytes))
	out = append(out, HybridSignBytesDomain...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(chainID)))
	out = append(out, chainID...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(bodyWithoutPqcExt)))
	out = append(out, bodyWithoutPqcExt...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(authInfoBytes)))
	out = append(out, authInfoBytes...)
	return out
}

var errEmptyChainID = errors.New("pqc: hybrid sign-bytes v2: chainID is required")

// HybridSignBytes builds the form named by version (SignBytesV1 or SignBytesV2).
// There is no implicit form: any other version is an error.
func HybridSignBytes(version int, chainID string, bodyWithoutPqcExt, authInfoBytes []byte) ([]byte, error) {
	switch version {
	case SignBytesV1:
		return HybridSignBytesV1(bodyWithoutPqcExt, authInfoBytes), nil
	case SignBytesV2:
		if chainID == "" {
			return nil, errEmptyChainID
		}
		return HybridSignBytesV2(chainID, bodyWithoutPqcExt, authInfoBytes), nil
	default:
		return nil, fmt.Errorf("hybrid sign-bytes version must be %d or %d, got %d", SignBytesV1, SignBytesV2, version)
	}
}
