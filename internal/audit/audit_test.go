package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestLogAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return fixed }
	if err := l.Write(Entry{RunID: "r1", CertificateID: 1043, Target: "nginx", Step: StepActivate, Result: ResultOK,
		OldSerial: "01", NewSerial: "02", PreviousRef: `{"id":"x"}`}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	// Reopening appends.
	l, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Entry{RunID: "r2", CertificateID: 1043, Step: StepVerify, Result: ResultFailed, Error: "boom"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	f, _ := os.Open(path)
	defer func() { _ = f.Close() }()
	var entries []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line is not JSON: %s", sc.Text())
		}
		entries = append(entries, m)
	}
	if len(entries) != 2 {
		t.Fatalf("%d entries", len(entries))
	}
	first := entries[0]
	if first["time"] != "2026-10-10T09:00:00Z" || first["run_id"] != "r1" || first["certificate_id"] != float64(1043) ||
		first["target"] != "nginx" || first["step"] != "activate" || first["result"] != "ok" ||
		first["old_serial"] != "01" || first["new_serial"] != "02" || first["previous_ref"] != `{"id":"x"}` {
		t.Errorf("first entry = %v", first)
	}
	if _, ok := first["error"]; ok {
		t.Error("empty error field written")
	}
	if entries[1]["error"] != "boom" {
		t.Errorf("second entry = %v", entries[1])
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode %o, want 600", info.Mode().Perm())
		}
	}
}
