package cve20258088

import (
	"context"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	LinuxName = "cve/cve-2025-8088-linux"
)

type LinuxDetector struct{}

func NewLinux() detector.Detector {
	return &LinuxDetector{}
}

func (LinuxDetector) Name() string { return LinuxName }
func (LinuxDetector) Version() int { return 0 }

// Requirements: Linux only, but we don’t need direct FS or running system
func (LinuxDetector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS: plugin.OSLinux,
	}
}

// No extractors required for dummy
func (LinuxDetector) RequiredExtractors() []string {
	return []string{}
}

// The finding structure for CVE (same as Windows, but not actually triggered)
func (LinuxDetector) DetectedFinding() inventory.Finding {
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2025-8088",
			Summary: "WinRAR path traversal vulnerability (<7.13)",
			Details: "Dummy Linux detector implementation — no scanning performed.",
		},
	}}}
}

// Dummy Scan: Always returns no findings on Linux
func (LinuxDetector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	// WinRAR is not relevant to Linux, so no findings
	return inventory.Finding{}, nil
}
