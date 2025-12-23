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

package rust_test

import (
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/reachability/rust"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	vpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
)

var binaryPathsFile = "testdata/mock_data/mock_binarypaths.json"
var extractedSymbolsFile = "testdata/mock_data/mock_extractedsymbols.json"
var testProjPath = "testdata/real-rust-project"

func Test_Enrich(t *testing.T) {
	tests := []struct {
		name          string
		vulnFile      string
		rustAvailable bool
		wantErr       error
		wantSignals   []*vex.FindingExploitabilitySignal
	}{
		{
			name:          "rust_toolchain_not_available",
			vulnFile:      "",
			rustAvailable: false,
			wantErr:       rust.ErrNoRustToolchain,
			wantSignals:   nil,
		},
		{
			name:          "empty_inventory",
			vulnFile:      "",
			rustAvailable: true,
			wantErr:       nil,
			wantSignals:   nil,
		},
		{
			name:          "vuln_func_level_data_not_exist",
			vulnFile:      "testdata/mock_data/vuln_nofunc.json",
			rustAvailable: true,
			wantErr:       nil,
			wantSignals:   []*vex.FindingExploitabilitySignal{},
		},
		{
			name:          "vuln_reachable",
			vulnFile:      "testdata/mock_data/vuln_reachable.json",
			rustAvailable: true,
			wantErr:       nil,
			wantSignals:   []*vex.FindingExploitabilitySignal{},
		},
		{
			name:          "vuln_fuzzymatch_reachable",
			vulnFile:      "testdata/mock_data/vuln_fuzzymatch.json",
			rustAvailable: true,
			wantErr:       nil,
			wantSignals:   []*vex.FindingExploitabilitySignal{},
		},
		{
			name:          "vuln_unreachable",
			vulnFile:      "testdata/mock_data/vuln_unreachable.json",
			rustAvailable: true,
			wantErr:       nil,
			wantSignals: []*vex.FindingExploitabilitySignal{
				{
					Plugin:        rust.Name,
					Justification: vex.VulnerableCodeNotInExecutePath,
				},
			},
		},
	}

	input := &enricher.ScanInput{
		ScanRoot: &fs.ScanRoot{
			Path: testProjPath,
			FS:   fs.DirFS("."),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// TEMP: replacing with real client to test on macos and windows runner on github
			// mockCli, err := newMockClient(binaryPathsFile, extractedSymbolsFile, tc.rustAvailable)
			// if err != nil {
			// 	t.Fatalf("failed to create mock client: %v", err)
			// }
			// e := rust.NewWithClient(mockCli, &cpb.PluginConfig{})

			e := rust.New(&cpb.PluginConfig{})

			var inv *inventory.Inventory
			if tc.vulnFile != "" {
				vuln := loadVuln(t, tc.vulnFile)
				inv = setupInventory(t, vuln)
			} else {
				inv = &inventory.Inventory{}
			}

			enrichErr := e.Enrich(t.Context(), input, inv)

			if enrichErr != nil {
				if !errors.Is(enrichErr, tc.wantErr) {
					t.Errorf("Enrich() error = %v, wantErr %v", enrichErr, tc.wantErr)
				}
				return
			}

			if tc.vulnFile == "" {
				if len(inv.PackageVulns) != 0 {
					t.Errorf("expected 0 PackageVulns, got %d", len(inv.PackageVulns))
				}
				return
			}

			gotSignals := inv.PackageVulns[0].ExploitabilitySignals
			if diff := cmp.Diff(tc.wantSignals, gotSignals, protocmp.Transform()); diff != "" {
				t.Errorf("ExploitabilitySignals mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func loadVuln(t *testing.T, path string) *vpb.Vulnerability {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read vuln file %s: %v", path, err)
	}

	vuln := &vpb.Vulnerability{}
	if err := protojson.Unmarshal(content, vuln); err != nil {
		t.Fatalf("failed to unmarshal vuln from %s: %v", path, err)
	}

	return vuln
}

func setupInventory(t *testing.T, vuln *vpb.Vulnerability) *inventory.Inventory {
	t.Helper()
	return &inventory.Inventory{
		PackageVulns: []*inventory.PackageVuln{
			{
				Vulnerability:         vuln,
				Package:               &extractor.Package{},
				Plugins:               []string{},
				ExploitabilitySignals: []*vex.FindingExploitabilitySignal{},
			},
		},
	}
}
