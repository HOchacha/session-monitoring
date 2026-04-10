package collector

import "testing"

func TestNormalizePrefixes(t *testing.T) {
	got := normalizePrefixes([]string{" VNET ", "", "CloudBr", "  "})
	if len(got) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(got))
	}
	if got[0] != "vnet" || got[1] != "cloudbr" {
		t.Fatalf("unexpected normalized prefixes: %#v", got)
	}
}

func TestHasPrefix(t *testing.T) {
	if !hasPrefix("vnet12", []string{"vnet", "tun"}) {
		t.Fatal("expected vnet12 to match")
	}
	if hasPrefix("enp134s0f0", []string{"vnet", "tun"}) {
		t.Fatal("expected enp134s0f0 to not match")
	}
}
