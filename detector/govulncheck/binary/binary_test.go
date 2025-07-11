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

package binary_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const binaryName = "semaphore-demo-go"

func TestScan(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}
	// Govulncheck expects the path to be file:///c:/something
	if runtime.GOOS == "windows" {
		wd = "/" + wd
	}
	det := binary.Detector{
		OfflineVulnDBPath: filepath.ToSlash(filepath.Join(wd, "testdata", "vulndb")),
	}
	px := setupPackageIndex([]string{binaryName})
	findings, err := det.Scan(context.Background(), scalibrfs.RealFSScanRoot("."), px)
	if err != nil {
		t.Fatalf("detector.Scan(%v): %v", px, err)
	}
	// There are two vulns in the test vulndb defined for two
	// module dependencies of the test binary. Both dependencies
	// are used at a vulnerable version. However, for only one
	// there is a vulnerable symbol present in the binary.
	if len(findings.PackageVulns) != 1 {
		t.Fatalf("detector.Scan(%v): expected 1 finding, got: %v", px, findings.PackageVulns)
	}
	got := findings.PackageVulns[0]
	want := &inventory.PackageVuln{
		Vulnerability: osvschema.Vulnerability{
			ID:      "GO-2022-1144",
			Aliases: []string{"CVE-2022-41717", "GHSA-xrjj-mj9h-534m"},
			Summary: "Excessive memory growth in net/http and golang.org/x/net/http2",
			Details: "An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests.\n\n" +
				"HTTP/2 server connections contain a cache of HTTP header keys sent by the client. While the total " +
				"number of entries in this cache is capped, an attacker sending very large keys can cause the " +
				"server to allocate approximately 64 MiB per open connection.",
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{Ecosystem: "Go", Name: "stdlib"},
				},
			},
			References: []osvschema.Reference{
				{Type: "REPORT", URL: "https://go.dev/issue/56350"},
				{Type: "FIX", URL: "https://go.dev/cl/455717"},
				{Type: "FIX", URL: "https://go.dev/cl/455635"},
				{
					Type: "WEB",
					URL:  "https://groups.google.com/g/golang-announce/c/L_3rmdT0BMU/m/yZDrXjIiBQAJ",
				},
			},
			Credits: []osvschema.Credit{{Name: "Josselin Costanzi"}},
		},
	}

	// Remove some fields that might change between govulncheck versions.
	got.Vulnerability.SchemaVersion = ""
	got.Vulnerability.Modified = time.Time{}
	got.Vulnerability.Published = time.Time{}
	got.Vulnerability.Withdrawn = time.Time{}
	got.Vulnerability.Affected = []osvschema.Affected{got.Vulnerability.Affected[0]}
	got.Vulnerability.Affected[0].Ranges = nil
	got.Vulnerability.Affected[0].EcosystemSpecific = nil
	got.Vulnerability.DatabaseSpecific = nil

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("detector.Scan(%v): unexpected findings (-want +got):\n%s", px, diff)
	}
}

func TestScanErrorInGovulncheck(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}
	// Govulncheck expects the path to be file:///c:/something
	if runtime.GOOS == "windows" {
		wd = "/" + wd
	}
	det := binary.Detector{
		OfflineVulnDBPath: filepath.ToSlash(filepath.Join(wd, "testdata", "vulndb")),
	}
	px := setupPackageIndex([]string{"nonexistent", binaryName})
	result, err := det.Scan(context.Background(), scalibrfs.RealFSScanRoot("."), px)
	if err == nil {
		t.Fatalf("detector.Scan(%v): Expected an error, got none", px)
	}
	if len(result.PackageVulns) == 0 {
		t.Fatalf("detector.Scan(%v): Expected scan results, got none", px)
	}
}

func setupPackageIndex(names []string) *packageindex.PackageIndex {
	pkgs := []*extractor.Package{}
	for _, n := range names {
		pkgs = append(pkgs, &extractor.Package{
			Name:      n,
			Version:   "1.2.3",
			PURLType:  purl.TypeGolang,
			Locations: []string{filepath.Join("testdata", n)},
			Plugins:   []string{gobinary.Name},
		})
	}
	px, _ := packageindex.New(pkgs)
	return px
}
