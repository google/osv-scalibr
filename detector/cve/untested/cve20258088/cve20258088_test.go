package cve20258088

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
)

// helper to run the detector
func runDetector(t *testing.T, f fs.FS, pkgs []*extractor.Package) inventory.Finding {
	t.Helper()
	scanRoot := &fs.ScanRoot{
		FS:   f,
		Path: ".",
	}
	px, err := packageindex.New(pkgs)
	if err != nil {
		t.Fatalf("packageindex.New() returned error: %v", err)
	}
	d := New()
	finding, err := d.Scan(context.Background(), scanRoot, px)
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}
	return finding
}

func TestNoFindings(t *testing.T) {
	// Empty FS, no packages
	finding := runDetector(t, fstest.MapFS{}, nil)
	if len(finding.PackageVulns) != 0 {
		t.Errorf("Expected no findings, got %d", len(finding.PackageVulns))
	}
}

func TestInstalledWinRARAffected(t *testing.T) {
	pkgs := []*extractor.Package{{
		Name:    "WinRAR",
		Version: "6.23", // vulnerable
	}}

	finding := runDetector(t, fstest.MapFS{}, pkgs)
	if len(finding.PackageVulns) == 0 {
		t.Fatalf("Expected a finding for vulnerable WinRAR package")
	}
	v := finding.PackageVulns[0]
	if v.Vulnerability.ID != "CVE-2025-8088" {
		t.Errorf("Unexpected vuln ID: %s", v.Vulnerability.ID)
	}
}

func TestInstalledWinRARSafe(t *testing.T) {
	pkgs := []*extractor.Package{{
		Name:    "WinRAR",
		Version: "7.20", // safe
	}}

	finding := runDetector(t, fstest.MapFS{}, pkgs)
	if len(finding.PackageVulns) != 0 {
		t.Fatalf("Expected no finding for safe WinRAR version, got %+v", finding)
	}
}

func TestFileSystemWinRARPortable(t *testing.T) {
	fs := fstest.MapFS{
		"WinRAR610.exe": &fstest.MapFile{Data: []byte{}}, // filename heuristic should trigger vuln
	}

	finding := runDetector(t, fs, nil)
	if len(finding.PackageVulns) == 0 {
		t.Fatalf("Expected finding from portable WinRAR exe, got none")
	}
	got := finding.PackageVulns[0]
	if got.Package.Name != "WinRAR" {
		t.Errorf("Expected package name WinRAR, got %s", got.Package.Name)
	}
	if !isAffectedVersion(got.Package.Version) {
		t.Errorf("Expected affected version, got %s", got.Package.Version)
	}
}

func TestNormalizeVersion(t *testing.T) {
	cases := map[string]string{
		"6_10": "6.10",
		"6-23": "6.23",
		"7.01": "7.01",
	}
	for in, want := range cases {
		if got := normalizeVersion(in); got != want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsAffectedVersion(t *testing.T) {
	cases := map[string]bool{
		"6.23": true,  // vulnerable
		"7.01": true,  // still vulnerable
		"7.13": false, // fixed
		"7.20": false, // safe
	}
	for ver, want := range cases {
		if got := isAffectedVersion(ver); got != want {
			t.Errorf("isAffectedVersion(%q) = %v, want %v", ver, got, want)
		}
	}
}
