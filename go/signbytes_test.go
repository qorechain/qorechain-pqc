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

func TestSignBytesUpgradeNames(t *testing.T) {
	if len(SignBytesV2Upgrades) != 2 || SignBytesV2Upgrades[0] != "v3.2.0" || SignBytesV2Upgrades[1] != "v3.1.98" {
		t.Fatalf("SignBytesV2Upgrades = %v, want [v3.2.0 v3.1.98]", SignBytesV2Upgrades)
	}
	if SignBytesV2Upgrade != "v3.2.0" {
		t.Fatalf("SignBytesV2Upgrade = %q, want the primary name v3.2.0", SignBytesV2Upgrade)
	}
}

func TestSignBytesVersionForApplied(t *testing.T) {
	cases := []struct {
		name    string
		chain   string
		applied map[string]int64
		want    int
	}{
		{"mainnet v3.2.0 only", "qorechain-vladi", map[string]int64{"v3.2.0": 2981742}, SignBytesV2},
		{"testnet v3.1.98 only", "qorechain-diana", map[string]int64{"v3.1.98": 5746000}, SignBytesV2},
		{"vladi v3.1.98 only", "qorechain-vladi", map[string]int64{"v3.1.98": 10}, SignBytesV2},
		{"diana v3.2.0 only", "qorechain-diana", map[string]int64{"v3.2.0": 10}, SignBytesV2},
		{"both applied", "qorechain-vladi", map[string]int64{"v3.2.0": 20, "v3.1.98": 10}, SignBytesV2},
		{"vladi neither (zeros)", "qorechain-vladi", map[string]int64{"v3.2.0": 0, "v3.1.98": 0}, SignBytesV1},
		{"vladi neither (nil)", "qorechain-vladi", nil, SignBytesV1},
		{"diana neither", "qorechain-diana", map[string]int64{}, SignBytesV1},
		{"unknown name ignored", "qorechain-vladi", map[string]int64{"v9.9.9": 100}, SignBytesV1},
		{"other chain neither", "qorechain-other", nil, SignBytesV2},
		{"other chain applied", "qorechain-other", map[string]int64{"v3.2.0": 5}, SignBytesV2},
	}
	for _, c := range cases {
		if got := SignBytesVersionForApplied(c.chain, c.applied); got != c.want {
			t.Fatalf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestHybridSignBytesV2RefusesEmptyChainID(t *testing.T) {
	if _, err := HybridSignBytes(SignBytesV2, "", []byte{1}, []byte{2}); err == nil {
		t.Fatal("dispatcher must refuse an empty chain-id for v2")
	}
	// v1 has no chain-id, so an empty one is fine there.
	if _, err := HybridSignBytes(SignBytesV1, "", []byte{1}, []byte{2}); err != nil {
		t.Fatalf("v1 must not need a chain-id: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("HybridSignBytesV2 must panic on an empty chain-id")
		}
	}()
	HybridSignBytesV2("", []byte{1}, []byte{2})
}
