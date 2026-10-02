package gomod

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/fs"
)

func TestGoSumSymlinkEscape(t *testing.T) {
	tmpDir := t.TempDir()
	scanRoot := filepath.Join(tmpDir, "scan-root")
	if err := os.MkdirAll(scanRoot, 0755); err != nil {
		t.Fatal(err)
	}

	// File rahasia di luar root (format go.sum valid)
	secretFile := filepath.Join(tmpDir, "secret.gosum")
	secretContent := "github.com/example/fake v1.0.0\n"
	if err := os.WriteFile(secretFile, []byte(secretContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Symlink di dalam root bernama go.sum
	symlinkPath := filepath.Join(scanRoot, "go.sum")
	if err := os.Symlink(secretFile, symlinkPath); err != nil {
		t.Fatal(err)
	}

	// File go.mod minimal sebagai pemicu extractor
	goModPath := filepath.Join(scanRoot, "go.mod")
	if err := os.WriteFile(goModPath, []byte("module example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	extractor := &Extractor{}
	input := &filesystem.ScanInput{
		Path: goModPath,
		FS:   fs.DirFS(scanRoot),
		Info: mustStat(t, goModPath),
	}

	inv, err := extractor.Extract(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	// Verifikasi package dari symlink terbaca
	found := false
	for _, pkg := range inv.Packages {
		if pkg.Name == "github.com/example/fake" && pkg.Version == "v1.0.0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected package from symlinked go.sum to appear, got %+v", inv.Packages)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
