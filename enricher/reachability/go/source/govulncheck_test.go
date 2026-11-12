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

// Copyright 2026 Google LLC
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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	govcsource "github.com/google/osv-scalibr/enricher/reachability/go/source"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/purl"
	vulnpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

const testProjPath = "./testdata/goproj"
const vulndbPath = "./testdata/vulndb"
const reachableVulnID = "GO-2023-1558"
const unreachableVulnID1 = "GO-2021-0053"
const unreachableVulnID2 = "GO-2024-2937"

func TestEnricher(t *testing.T) {
	testCases := []struct {
		name            string
		vulnID          string
		expectedSignals []*vex.FindingExploitabilitySignal
	}{
		{
			name:            "reachable vuln",
			vulnID:          reachableVulnID,
			expectedSignals: nil,
		},
		{
			name:   "unreachable vuln 1 (package imported, vulnerable function not called)",
			vulnID: unreachableVulnID1,
			expectedSignals: []*vex.FindingExploitabilitySignal{{
				Plugin:        govcsource.Name,
				Justification: vex.VulnerableCodeNotInExecutePath,
			}},
		},
		{
			name:   "unreachable vuln 2 (package not imported at all, just present in go.mod)",
			vulnID: unreachableVulnID2,
			expectedSignals: []*vex.FindingExploitabilitySignal{{
				Plugin:        govcsource.Name,
				Justification: vex.VulnerableCodeNotInExecutePath,
			}},
		},
	}

	pkgs := setupPackages(t)
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

	gvcClient, err := newMockGovulncheckClient("testdata/govulncheckinput.json", nil, true)
	if err != nil {
		t.Fatalf("failed to create mock govulncheck client: %v", err)
	}
	enr := govcsource.NewWithClient(&cpb.PluginConfig{}, gvcClient)

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

func TestEnricher_GoVersion(t *testing.T) {
	testCases := []struct {
		name          string
		pkgs          []*extractor.Package
		wantGoVersion string
	}{
		{
			name: "without stdlib package",
			pkgs: []*extractor.Package{
				{
					Name:     "github.com/ipfs/go-bitfield",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPath(filepath.Join(".", "go.mod")),
					Plugins:  []string{gomod.Name},
				},
			},
			wantGoVersion: "",
		},
		{
			name: "with stdlib package",
			pkgs: []*extractor.Package{
				{
					Name:     "github.com/ipfs/go-bitfield",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPath(filepath.Join(".", "go.mod")),
					Plugins:  []string{gomod.Name},
				},
				{
					Name:     "stdlib",
					Version:  "1.19",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPath(filepath.Join(".", "go.mod")),
					Plugins:  []string{gomod.Name},
				},
			},
			wantGoVersion: "1.19",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gvcClient, err := newMockGovulncheckClient("testdata/govulncheckinput.json", nil, true)
			if err != nil {
				t.Fatalf("failed to create mock govulncheck client: %v", err)
			}
			enr := govcsource.NewWithClient(&cpb.PluginConfig{}, gvcClient)
			input := enricher.ScanInput{
				ScanRoot: &scalibrfs.ScanRoot{
					Path: testProjPath,
					FS:   scalibrfs.DirFS("."),
				},
			}
			inv := inventory.Inventory{
				Packages:     tc.pkgs,
				PackageVulns: setupPackageVulns(t, tc.pkgs),
			}
			if err := enr.Enrich(t.Context(), &input, &inv); err != nil {
				t.Fatalf("enr.Enrich() failed: %v", err)
			}
			if gvcClient.gotGoVersion != tc.wantGoVersion {
				t.Errorf("RunGovulncheck goVersion = %q, want %q", gvcClient.gotGoVersion, tc.wantGoVersion)
			}
		})
	}
}

func setupPackages(t *testing.T) []*extractor.Package {
	t.Helper()
	extr, err := gomod.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("gomod.New() error: %v", err)
	}
	goModContent := strings.Join([]string{
		"module example.com/test",
		"",
		"go 1.19",
		"",
		"require (",
		"\t// Affected by GO-2021-0053, but we don't actually call the vulnerable func",
		"\tgithub.com/gogo/protobuf v1.3.1",
		"\t// Affected by GO-2023-1558, and we do call the vulnerable func",
		"\tgithub.com/ipfs/go-bitfield v1.0.0",
		"\t// Affected by GO-2024-2937, but only present in the go.mod file, not in the code",
		"\tgolang.org/x/image v0.4.0",
		")",
		"",
	}, "\n")
	inv, err := extr.Extract(t.Context(), &filesystem.ScanInput{
		Path:   filepath.Join(".", "go.mod"),
		Root:   testProjPath,
		Reader: strings.NewReader(goModContent),
		FS:     scalibrfs.DirFS("."),
	})
	if err != nil {
		t.Fatalf("gomod.Extract() error: %v", err)
	}
	for _, pkg := range inv.Packages {
		pkg.Plugins = []string{extr.Name()}
	}
	return inv.Packages
}

func setupPackageVulns(t *testing.T, pkgs []*extractor.Package) []*inventory.PackageVuln {
	t.Helper()
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

func loadVuln(t *testing.T, vulnID string) *vulnpb.Vulnerability {
	t.Helper()
	path := filepath.Join(vulndbPath, vulnID+".json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read vuln file %s: %v", path, err)
	}

	vuln := &vulnpb.Vulnerability{}
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
