package cve20258088

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/semantic"
)

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
	d := &Detector{}
	finding, err := d.Scan(context.Background(), scanRoot, px)
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}
	return finding
}

func TestNoFindings(t *testing.T) {
	finding := runDetector(t, fstest.MapFS{}, nil)
	if len(finding.PackageVulns) != 0 {
		t.Errorf("Expected no findings, got %d", len(finding.PackageVulns))
	}
}

func TestInstalledWinRARAffected(t *testing.T) {
	pkgs := []*extractor.Package{{
		Name:    "WinRAR",
		Version: "6.23",
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
		Version: "7.20",
	}}

	finding := runDetector(t, fstest.MapFS{}, pkgs)
	if len(finding.PackageVulns) != 0 {
		t.Fatalf("Expected no finding for safe WinRAR version, got %+v", finding)
	}
}

func TestFileSystemWinRARPortable(t *testing.T) {
	// Simulate what the PE version extractor would find for WinRAR610.exe
	pkgs := []*extractor.Package{
		{
			Name:      "WinRAR",
			Version:   "6.10",
			PURLType:  "generic",
			Locations: []string{"WinRAR610.exe"},
		},
	}

	finding := runDetector(t, fstest.MapFS{}, pkgs)
	if len(finding.PackageVulns) == 0 {
		t.Fatalf("Expected finding from portable WinRAR exe, got none")
	}
	got := finding.PackageVulns[0]
	if got.Package.Name != "WinRAR" && got.Package.Name != "winrar" {
		t.Errorf("Expected package name WinRAR, got %s", got.Package.Name)
	}

	sv, err := semantic.Parse(got.Package.Version, "Maven")
	if err != nil {
		t.Errorf("Failed to parse version: %v", err)
	}
	cmp, err := sv.CompareStr("7.13")
	if err != nil {
		t.Errorf("Failed to compare version: %v", err)
	}
	if cmp >= 0 {
		t.Errorf("Expected affected version, got %s", got.Package.Version)
	}
}
