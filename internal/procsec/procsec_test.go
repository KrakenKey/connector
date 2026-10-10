//go:build linux

package procsec

import "testing"

func TestHarden(t *testing.T) {
	if err := Harden(); err != nil {
		t.Fatal(err)
	}
	d, err := Dumpable()
	if err != nil || d {
		t.Errorf("dumpable = %v, %v; want false", d, err)
	}
}
