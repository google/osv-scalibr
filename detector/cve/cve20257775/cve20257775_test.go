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
	"path"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/detector/cve/cve20257775"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
)

func TestScan(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("%v", err)
	}

	pkgs := []*extractor.Package{{
		Name:    "NetScaler",
		Version: "14.1-47.47", // Vulnerable version
		Locations: []string{
			path.Join(dir, "testdata/valid.vmdk:1:/flash/boot/loader.conf"),
		},
		Metadata: scalibrfs.DirFS(path.Join(dir, "testdata")),
	},
		{
			Name:    "NetScaler",
			Version: "14.1-47.48", // Benign Version
			Locations: []string{
				path.Join(dir, "testdata/valid.vmdk:2:/flash/boot/loader.conf"),
			},
			Metadata: scalibrfs.DirFS(path.Join(dir, "testdata")),
		},
		{
			Name:    "NetScaler",
			Version: "13.1-59.21", // Vulnerable version
			Locations: []string{
				path.Join(dir, "testdata/valid.vmdk:3:/flash/boot/loader.conf"),
			},
			Metadata: scalibrfs.DirFS(path.Join(dir, "testdata")),
		},
		{
			Name:    "NetScaler",
			Version: "13.1-59.22", // Benign Version
			Locations: []string{
				path.Join(dir, "testdata/valid.vmdk:4:/flash/boot/loader.conf"),
			},
			Metadata: scalibrfs.DirFS(path.Join(dir, "testdata")),
		},
		{
			Name:    "NetScaler",
			Version: "12.1-55.329", // Vulnerable version
			Locations: []string{
				path.Join(dir, "testdata/valid.vmdk:5:/flash/boot/loader.conf"),
			},
			Metadata: scalibrfs.DirFS(path.Join(dir, "testdata")),
		},
		{
			Name:    "NetScaler",
			Version: "12.1-55.330", // Benign Version
			Locations: []string{
				path.Join(dir, "testdata/valid.vmdk:6:/flash/boot/loader.conf"),
			},
			Metadata: scalibrfs.DirFS(path.Join(dir, "testdata")),
		},
		// For the following two packages, it must return only one security findings
		// because in a filesystem there can be more than one place where we can
		// find the version strings but we don't need to report all the version
		// strings as unique findings.
		{
			Name:    "NetScaler",
			Version: "12.1-55.123", // Vulnerable Version
			Locations: []string{
				path.Join(dir, "testdata/flash/boot/loader.conf"),
			},
			Metadata: scalibrfs.DirFS(path.Join(dir, "testdata")),
		},
		{
			Name:    "NetScaler",
			Version: "12.1-55.123", // Vulnerable Version
			Locations: []string{
				path.Join(dir, "testdata/flash/boot/ns-12.1-55.123.gz"),
			},
			Metadata: scalibrfs.DirFS(path.Join(dir, "testdata")),
		}}

	finding := runScan(t, fstest.MapFS{}, pkgs)

	if len(finding.PackageVulns) != 4 {
		t.Fatalf("Expected 4 finding got %d", len(finding.PackageVulns))
	}

	v := finding.PackageVulns[0]
	if v.Vulnerability.Id != "CVE-2025-7775" {
		t.Errorf("Unexpected vuln ID: %s", v.Vulnerability.Id)
	}
}

func runScan(t *testing.T, fs scalibrfs.FS, pkgs []*extractor.Package) inventory.Finding {
	t.Helper()
	px, err := packageindex.New(pkgs)
	if err != nil {
		t.Fatalf("packageindex.New() returned error: %v", err)
	}
	scanRoot := &scalibrfs.ScanRoot{
		FS:   fs,
		Path: ".",
	}
	detector := cve20257775.New()
	findings, err := detector.Scan(context.Background(), scanRoot, px)
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}
	return findings
}
