package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReleaseBuildsNeverUseFakeAzure fails if a release or packaging file
// in the repository mentions the fakeazure build tag, which swaps in a
// static token and a test endpoint. Only this package's tests may use it.
func TestReleaseBuildsNeverUseFakeAzure(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("repository root not found at %s", root)
	}
	var files []string
	for _, pattern := range []string{
		"goreleaser.y*ml", ".goreleaser.y*ml", "Dockerfile*", "Makefile",
		".github/workflows/*.y*ml",
		"plugins/*/goreleaser.y*ml", "plugins/*/.goreleaser.y*ml", "plugins/*/Dockerfile*", "plugins/*/Makefile",
	} {
		m, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("found no release files to check")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "fakeazure") {
			t.Errorf("%s mentions the fakeazure build tag; release builds must not use it", f)
		}
	}
}
