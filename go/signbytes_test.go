package pqc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type signBytesKAT struct {
	HybridDomain string `json:"hybrid_domain"`
	HybridV2     []struct {
		Name      string `json:"name"`
		ChainID   string `json:"chain_id"`
		B0Hex     string `json:"body_without_pqc_ext_hex"`
		AuthHex   string `json:"auth_info_hex"`
		SignBytes string `json:"sign_bytes_hex"`
	} `json:"hybrid_v2"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHybridSignBytesV2KAT(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "vectors", "signbytes-kat-v3.1.98.json"))
	if err != nil {
		t.Fatal(err)
	}
	var kat signBytesKAT
	if err := json.Unmarshal(raw, &kat); err != nil {
		t.Fatal(err)
	}
	if kat.HybridDomain != HybridSignBytesDomain {
		t.Fatalf("domain %q != %q", kat.HybridDomain, HybridSignBytesDomain)
	}
	if len(kat.HybridV2) != 5 {
		t.Fatalf("expected 5 hybrid_v2 vectors, got %d", len(kat.HybridV2))
	}
	for _, v := range kat.HybridV2 {
		b0, a := mustHex(t, v.B0Hex), mustHex(t, v.AuthHex)
		if got := hex.EncodeToString(HybridSignBytesV2(v.ChainID, b0, a)); got != v.SignBytes {
			t.Fatalf("%s: got %s want %s", v.Name, got, v.SignBytes)
		}
		got, err := HybridSignBytes(SignBytesV2, v.ChainID, b0, a)
		if err != nil || hex.EncodeToString(got) != v.SignBytes {
			t.Fatalf("%s: dispatcher mismatch (%v)", v.Name, err)
		}
	}
}

func TestHybridSignBytesV1AndDispatch(t *testing.T) {
	want := []byte{0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9}
	if !bytes.Equal(HybridSignBytesV1([]byte{1, 2, 3}, []byte{9, 9}), want) {
		t.Fatal("v1 layout wrong")
	}
	got, err := HybridSignBytes(SignBytesV1, "qorechain-vladi", []byte{1, 2, 3}, []byte{9, 9})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("v1 dispatch wrong")
	}
	for _, bad := range []int{0, 3, -1} {
		if _, err := HybridSignBytes(bad, "qorechain-vladi", nil, nil); err == nil {
			t.Fatalf("version %d must be rejected", bad)
		}
	}
}

func TestSignBytesVersionFor(t *testing.T) {
	cases := []struct {
		chain string
		h     int64
		want  int
	}{
		{"qorechain-vladi", 0, SignBytesV1}, {"qorechain-vladi", 5746000, SignBytesV2},
		{"qorechain-diana", 0, SignBytesV1}, {"qorechain-diana", 5746000, SignBytesV2},
		{"qorechain-other", 0, SignBytesV2}, {"qorechain-other", 5746000, SignBytesV2},
	}
	for _, c := range cases {
		if got := SignBytesVersionFor(c.chain, c.h); got != c.want {
			t.Fatalf("%s@%d: got %d want %d", c.chain, c.h, got, c.want)
		}
	}
}

func TestV2SignatureDoesNotVerifyOverV1(t *testing.T) {
	pk, sk, err := MLDSA.Keygen()
	if err != nil {
		t.Fatal(err)
	}
	v2 := HybridSignBytesV2("qorechain-vladi", []byte{1, 2, 3}, []byte{9})
	v1 := HybridSignBytesV1([]byte{1, 2, 3}, []byte{9})
	sig, err := MLDSA.Sign(sk, v2)
	if err != nil {
		t.Fatal(err)
	}
	if !MLDSA.Verify(pk, v2, sig) || MLDSA.Verify(pk, v1, sig) {
		t.Fatal("v2 signature must verify over v2 bytes only")
	}
}
