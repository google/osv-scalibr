package cve20258088

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/purl"
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

func TestScan(t *testing.T) {
	tests := []struct {
		name         string
		pkgs         []*extractor.Package
		wantFindings int
		wantVulnID   string
	}{
		{
			name:         "no_packages",
			pkgs:         nil,
			wantFindings: 0,
		},
		{
			name: "vulnerable_winrar_installed",
			pkgs: []*extractor.Package{{
				Name:    "WinRAR",
				Version: "6.23",
			}},
			wantFindings: 1,
			wantVulnID:   "CVE-2025-8088",
		},
		{
			name: "safe_winrar_version",
			pkgs: []*extractor.Package{{
				Name:    "WinRAR",
				Version: "7.20",
			}},
			wantFindings: 0,
		},
		{
			name: "vulnerable_portable_winrar",
			pkgs: []*extractor.Package{{
				Name:     "WinRAR",
				Version:  "6.10",
				PURLType: purl.TypeGeneric,
				Location: extractor.LocationFromPath("WinRAR610.exe"),
			}},
			wantFindings: 1,
			wantVulnID:   "CVE-2025-8088",
		},
		{
			name: "unrar_detected_as_vulnerable",
			pkgs: []*extractor.Package{{
				Name:    "UnRAR",
				Version: "5.0",
			}},
			wantFindings: 1,
			wantVulnID:   "CVE-2025-8088",
		},
		{
			name: "non_winrar_package_ignored",
			pkgs: []*extractor.Package{{
				Name:    "7-Zip",
				Version: "1.0",
			}},
			wantFindings: 0,
		},
		{
			name: "boundary_version_7.13_not_vulnerable",
			pkgs: []*extractor.Package{{
				Name:    "WinRAR",
				Version: "7.13",
			}},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := runDetector(t, fstest.MapFS{}, tt.pkgs)
			if got := len(finding.PackageVulns); got != tt.wantFindings {
				t.Fatalf("Scan() returned %d findings, want %d", got, tt.wantFindings)
			}
			if tt.wantFindings > 0 && finding.PackageVulns[0].Vulnerability.Id != tt.wantVulnID {
				t.Errorf("Vulnerability ID = %q, want %q", finding.PackageVulns[0].Vulnerability.Id, tt.wantVulnID)
			}
		})
	}
}
