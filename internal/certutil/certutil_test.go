package certutil

import (
	"math/big"
	"slices"
	"testing"
)

func TestNames(t *testing.T) {
	got := NormalizeNames([]string{" WWW.Example.com.", "api.example.com", "www.example.com", ""})
	if !slices.Equal(got, []string{"api.example.com", "www.example.com"}) {
		t.Errorf("NormalizeNames = %v", got)
	}
	if !SameNames([]string{"a.example.com", "B.example.com"}, []string{"b.example.com", "a.example.com"}) {
		t.Error("SameNames ignores order and case")
	}
	if SameNames([]string{"a.example.com"}, []string{"a.example.com", "b.example.com"}) {
		t.Error("SameNames accepted a superset")
	}
}

func TestSerialHex(t *testing.T) {
	if got := SerialHex(big.NewInt(0xABC)); got != "abc" {
		t.Errorf("SerialHex = %s", got)
	}
	if SerialHex(nil) != "" {
		t.Error("nil serial")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ParseLeaf("not pem"); err == nil {
		t.Error("ParseLeaf accepted garbage")
	}
	if _, err := ParseCSR("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"); err == nil {
		t.Error("ParseCSR accepted a certificate block")
	}
}
