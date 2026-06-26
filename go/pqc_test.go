package pqc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type sigVec struct {
	Cases []struct {
		PublicKey string `json:"publicKey"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	} `json:"cases"`
}
type kemVec struct {
	Cases []struct {
		SecretKey    string `json:"secretKey"`
		CipherText   string `json:"cipherText"`
		SharedSecret string `json:"sharedSecret"`
	} `json:"cases"`
}
type shakeVec struct {
	Cases []struct {
		Message string `json:"message"`
		Out32   string `json:"out32"`
		Out64   string `json:"out64"`
	} `json:"cases"`
}

func load(t *testing.T, name string, v any) {
	p := filepath.Join("..", "vectors", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}
func dh(t *testing.T, s string) []byte { b, err := hex.DecodeString(s); if err != nil { t.Fatal(err) }; return b }

func TestMLDSAVectors(t *testing.T) {
	for _, tc := range []struct {
		file string
		sc   SigScheme
	}{{"ml-dsa-44.json", MLDSA44}, {"ml-dsa-65.json", MLDSA65}, {"ml-dsa-87.json", MLDSA87}} {
		var v sigVec
		load(t, tc.file, &v)
		for i, c := range v.Cases {
			if !tc.sc.Verify(dh(t, c.PublicKey), dh(t, c.Message), dh(t, c.Signature)) {
				t.Fatalf("%s case %d failed to verify", tc.file, i)
			}
		}
	}
}

func TestMLKEMVectors(t *testing.T) {
	for _, tc := range []struct {
		file string
		kc   KemScheme
	}{{"ml-kem-512.json", MLKEM512}, {"ml-kem-768.json", MLKEM768}, {"ml-kem-1024.json", MLKEM1024}} {
		var v kemVec
		load(t, tc.file, &v)
		for i, c := range v.Cases {
			ss, err := tc.kc.Decapsulate(dh(t, c.SecretKey), dh(t, c.CipherText))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, dh(t, c.SharedSecret)) {
				t.Fatalf("%s case %d shared-secret mismatch", tc.file, i)
			}
		}
	}
}

func TestShake256Vectors(t *testing.T) {
	var v shakeVec
	load(t, "shake-256.json", &v)
	for i, c := range v.Cases {
		msg := dh(t, c.Message)
		if !bytes.Equal(Shake256(msg, 32), dh(t, c.Out32)) {
			t.Fatalf("shake case %d out32 mismatch", i)
		}
		if !bytes.Equal(Shake256(msg, 64), dh(t, c.Out64)) {
			t.Fatalf("shake case %d out64 mismatch", i)
		}
	}
}

func TestRoundtripAndHelpers(t *testing.T) {
	pk, sk, err := MLDSA.Keygen()
	if err != nil {
		t.Fatal(err)
	}
	sb := HybridSignBytes([]byte{1, 2, 3}, []byte{9, 9})
	if !bytes.Equal(sb, []byte{0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9}) {
		t.Fatal("hybrid framing wrong")
	}
	sig, err := MLDSA.Sign(sk, sb)
	if err != nil {
		t.Fatal(err)
	}
	if !MLDSA.Verify(pk, sb, sig) {
		t.Fatal("roundtrip verify failed")
	}
	if len(PubkeyHash(pk, 20)) != 20 {
		t.Fatal("pubkeyHash len")
	}
	ek, dk, _ := MLKEM.Keygen()
	ct, ss1, _ := MLKEM.Encapsulate(ek)
	ss2, _ := MLKEM.Decapsulate(dk, ct)
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("kem roundtrip mismatch")
	}
}
