// Copyright 2025 Google LLC
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
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/detector/cve/cve20257775"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/purl"
)

func TestScanValid(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("%v", err)
	}

	pkgs := []*extractor.Package{{
		Name:     "OVA",
		PURLType: purl.TypeOva,
		Locations: []string{
			filepath.Join(dir, "testdata", "valid.vmdk"),
			filepath.Join(dir, "testdata", "valid.vdi"),
		},
	}}

	finding := runScan(t, fstest.MapFS{}, pkgs, false)

	if len(finding.PackageVulns) != 2 {
		t.Fatalf("Expected %d finding", len(finding.PackageVulns))
	}

	v1 := finding.PackageVulns[0]
	if v1.Vulnerability.ID != "CVE-2025-7775" {
		t.Errorf("Unexpected vuln ID: %s", v1.Vulnerability.ID)
	}
	v2 := finding.PackageVulns[1]
	if v2.Vulnerability.ID != "CVE-2025-7775" {
		t.Errorf("Unexpected vuln ID: %s", v2.Vulnerability.ID)
	}
}

func TestScanInvalidExtension(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("%v", err)
	}
	pkgs := []*extractor.Package{{
		Name:      "OVA",
		PURLType:  purl.TypeOva,
		Locations: []string{filepath.Join(dir, "testdata", "invalid.extension")},
	}}
	finding := runScan(t, fstest.MapFS{}, pkgs, false)
	if len(finding.PackageVulns) != 0 {
		t.Errorf("Expected no findings, got %d", len(finding.PackageVulns))
	}
}

func TestScanNonExistent(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("%v", err)
	}
	pkgs := []*extractor.Package{{
		Name:     "OVA",
		PURLType: purl.TypeOva,
		Locations: []string{
			filepath.Join(dir, "testdata", "nonexisting.vmdk"),
			filepath.Join(dir, "testdata", "wrong.extension"),
		},
	}}
	finding := runScan(t, fstest.MapFS{}, pkgs, false)
	if len(finding.PackageVulns) != 0 {
		t.Errorf("Expected no findings, got %d", len(finding.PackageVulns))
	}
}

func runScan(t *testing.T, fs scalibrfs.FS, pkgs []*extractor.Package, hostScan bool) inventory.Finding {
	t.Helper()
	px, err := packageindex.New(pkgs)
	if err != nil {
		t.Fatalf("packageindex.New() returned error: %v", err)
	}
	scanRoot := &scalibrfs.ScanRoot{
		FS:   fs,
		Path: ".",
	}
	detector := cve20257775.New(cve20257775.Options{HostScan: hostScan})
	findings, err := detector.Scan(context.Background(), scanRoot, px)
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}
	return findings
}
