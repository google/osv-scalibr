// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package source_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	govcsource "github.com/google/osv-scalibr/enricher/govulncheck/source"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/purl"
)

const testProjPath = "./testdata/goproj"
const vulndbPath = "./testdata/vulndb"
const reachableVulnID = "GO-2023-1558"
const unreachableVulnID1 = "GO-2021-0053"
const unreachableVulnID2 = "GO-2024-2937"

func TestEnricher(t *testing.T) {
	testCases := []struct {
		name					string
		vulnID					string
		expectedSignals []*vex.FindingExploitabilitySignal
	}{
		{
			name:					"reachable vuln",
			vulnID:					reachableVulnID,
			expectedSignals: nil,
		},
		{
			name:					"unreachable vuln 1 (package imported, vulnerable function not called)",
			vulnID:					unreachableVulnID1,
			expectedSignals: []*vex.FindingExploitabilitySignal{{
				Plugin:        govcsource.Name,
				Justification: vex.VulnerableCodeNotInExecutePath,
			}},
		},
		{
			name:					"unreachable vuln 2 (package not imported at all, just present in go.mod)",
			vulnID:					unreachableVulnID2,
			expectedSignals: []*vex.FindingExploitabilitySignal{{
				Plugin:        govcsource.Name,
				Justification: vex.VulnerableCodeNotInExecutePath,
			}},
		},
	}

	pkgs := setupPackages()
	vulns := setupPackageVulns(t, pkgs)
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: testProjPath,
			FS:   scalibrfs.DirFS("."),
		},
	}

	inv := inventory.Inventory{
		Packages:     pkgs,
		PackageVulns: vulns,
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}
	// Govulncheck expects the path to be file:///c:/something
	if runtime.GOOS == "windows" {
		wd = "/" + wd
	}

	enr := govcsource.New(&cpb.PluginConfig{
		PluginSpecific: []*cpb.PluginSpecificConfig{
			{
				Config: &cpb.PluginSpecificConfig_Govulncheck{Govulncheck: &cpb.GovulncheckConfig{
					OfflineVulnDbPath: filepath.ToSlash(filepath.Join(wd, "testdata", "vulndb")),
				}}},
		},
	})

	err = enr.Enrich(t.Context(), &input, &inv)

	if err != nil {
		t.Fatalf("govulncheck enrich failed: %s", err)
	}

	vulnsByID := make(map[string]*inventory.PackageVuln)
	for _, v := range inv.PackageVulns {
		vulnsByID[v.Vulnerability.Id] = v
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vuln, ok := vulnsByID[tc.vulnID]
			if !ok {
				t.Fatalf("vulnerability %s not found in inventory", tc.vulnID)
			}

			if diff := cmp.Diff(tc.expectedSignals, vuln.ExploitabilitySignals); diff != "" {
				t.Errorf("ExploitabilitySignals mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func setupPackages() []*extractor.Package {
	pkgs := []*extractor.Package{
		{
			Name:      "stdlib",
			Version:   "1.19",
			PURLType:  purl.TypeGolang,
			Locations: []string{filepath.Join(".", "go.mod")},
			Plugins:   []string{gomod.Name},
		},
		// Affected by GO-2021-0053, but we don't actually call the vulnerable func
		{
			Name:      "github.com/gogo/protobuf",
			Version:   "1.3.1",
			PURLType:  purl.TypeGolang,
			Locations: []string{filepath.Join(".", "go.mod")},
			Plugins:   []string{gomod.Name},
		},
		// Affected by GO-2023-1558, and we do call the vulnerable func
		{
			Name:      "github.com/ipfs/go-bitfield",
			Version:   "1.0.0",
			PURLType:  purl.TypeGolang,
			Locations: []string{filepath.Join(".", "go.mod")},
			Plugins:   []string{gomod.Name},
		},
		// Affected by GO-2024-2937, but only present in the go.mod file, nor present in the code
		{
			Name:      "golang.org/x/image",
			Version:   "0.4.0",
			PURLType:  purl.TypeGolang,
			Locations: []string{filepath.Join(".", "go.mod")},
			Plugins:   []string{gomod.Name},
		},
	}

	return pkgs
}

func setupPackageVulns(t *testing.T, pkgs []*extractor.Package) []*inventory.PackageVuln {
	pkgVulns := []*inventory.PackageVuln{
		{
			Vulnerability: loadVuln(t, reachableVulnID),
			Package:       getRefToPackage(pkgs, "github.com/ipfs/go-bitfield"),
		},
		{
			Vulnerability: loadVuln(t, unreachableVulnID1),
			Package:       getRefToPackage(pkgs, "github.com/gogo/protobuf"),
		},
		{
			Vulnerability: loadVuln(t, unreachableVulnID2),
			Package:       getRefToPackage(pkgs, "golang.org/x/image"),
		},
	}

	return pkgVulns
}

func loadVuln(t *testing.T, vulnID string) *osvschema.Vulnerability {
	path := filepath.Join(vulndbPath, vulnID+".json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read vuln file %s: %v", path, err)
	}

	vuln := &osvschema.Vulnerability{}
	if err := protojson.Unmarshal(content, vuln); err != nil {
		t.Fatalf("failed to unmarshal vuln from %s: %v", path, err)
	}

	return vuln
}

func getRefToPackage(pkgs []*extractor.Package, name string) *extractor.Package {
	for _, pkg := range pkgs {
		if pkg.Name == name {
			return pkg
		}
	}
	return nil
}
