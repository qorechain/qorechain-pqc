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

const Version = "0.1.1"

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
func (sc SigScheme) Verify(publicKey, message, signature []byte) bool {
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

// HybridSignBytes is the canonical message a PQC signature covers in QoreChain's
// hybrid-extension scheme: BE32(len(b0))||b0||BE32(len(auth))||auth, where b0 is
// the tx body WITHOUT the PQC extension.
func HybridSignBytes(bodyWithoutPqcExt, authInfoBytes []byte) []byte {
	out := make([]byte, 0, 8+len(bodyWithoutPqcExt)+len(authInfoBytes))
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], uint32(len(bodyWithoutPqcExt)))
	out = append(out, be[:]...)
	out = append(out, bodyWithoutPqcExt...)
	binary.BigEndian.PutUint32(be[:], uint32(len(authInfoBytes)))
	out = append(out, be[:]...)
	out = append(out, authInfoBytes...)
	return out
}
