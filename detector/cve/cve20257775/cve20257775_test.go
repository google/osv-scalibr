// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cve20257775_test

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/detector/cve/cve20257775"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/fsmetadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestScan(t *testing.T) {
	dir := fakefs.CopyTestData(t, "testdata")
	fsys := scalibrfs.DirFS(dir)

	pkgs := []*extractor.Package{
		{
			Name:     "NetScaler",
			Version:  "14.1-47.47", // Vulnerable version
			Location: extractor.LocationFromPath(filepath.Join(dir, "valid.vmdk:1:flash", "boot", "loader.conf")),
			Metadata: &fsmetadata.Metadata{FS: fsys},
		},
		{
			Name:     "NetScaler",
			Version:  "14.1-47.48", // Benign Version
			Location: extractor.LocationFromPath(filepath.Join(dir, "valid.vmdk:2:flash", "boot", "loader.conf")),
			Metadata: &fsmetadata.Metadata{FS: fsys},
		},
		{
			Name:     "NetScaler",
			Version:  "13.1-59.21", // Vulnerable version
			Location: extractor.LocationFromPath(filepath.Join(dir, "valid.vmdk:3:ns-13.1-59.21.gz")),
			Metadata: &fsmetadata.Metadata{FS: fsys},
		},
		{
			Name:     "NetScaler",
			Version:  "13.1-59.22", // Benign Version
			Location: extractor.LocationFromPath(filepath.Join(dir, "valid.vmdk:4:ns-13.1-59.22.gz")),
			Metadata: &fsmetadata.Metadata{FS: fsys},
		},
		{
			Name:     "NetScaler",
			Version:  "12.1-55.329", // Vulnerable version
			Location: extractor.LocationFromPath(filepath.Join(dir, "valid.vmdk:5:nsversion")),
			Metadata: &fsmetadata.Metadata{FS: fsys},
		},
		{
			Name:     "NetScaler",
			Version:  "12.1-55.330", // Benign Version
			Location: extractor.LocationFromPath(filepath.Join(dir, "valid.vmdk:6:nsversion")),
			Metadata: &fsmetadata.Metadata{FS: fsys},
		},
	}

	finding := runScan(t, dir, pkgs)

	if len(finding.PackageVulns) != 3 {
		t.Fatalf("Expected 3 finding got %d", len(finding.PackageVulns))
	}

	v := finding.PackageVulns[0]
	if v.Vulnerability.Id != "CVE-2025-7775" {
		t.Errorf("Unexpected vuln ID: %s", v.Vulnerability.Id)
	}
}

func runScan(t *testing.T, dir string, pkgs []*extractor.Package) inventory.Finding {
	t.Helper()
	px, err := packageindex.New(pkgs)
	if err != nil {
		t.Fatalf("packageindex.New() returned error: %v", err)
	}
	detector, err := cve20257775.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("cve20257775.New() returned error: %v", err)
	}
	findings, err := detector.Scan(t.Context(), scalibrfs.RealFSScanRoot(dir), px)
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}
	return findings
}
