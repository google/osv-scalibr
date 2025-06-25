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

package relax_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/guidedremediation/internal/matchertest"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/relax"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

func TestComputePatches(t *testing.T) {
	npmRW, err := npm.GetReadWriter("")
	if err != nil {
		t.Fatalf("failed getting ReadWriter: %v", err)
	}
	tests := []struct {
		name         string
		universeFile string
		vulnsFile    string
		manifestPath string
		readWriter   manifest.ReadWriter
		opts         options.RemediationOptions
		wantFile     string
	}{
		{
			name:         "npm-simple",
			universeFile: "testdata/npm/universe.yaml",
			vulnsFile:    "testdata/npm/vulnerabilities.yaml",
			manifestPath: "npm/simple/package.json",
			readWriter:   npmRW,
			opts:         options.DefaultRemediationOptions(),
			wantFile:     "testdata/npm/simple/patches.json",
		},
		{
			name:         "npm-vuln-without-fix",
			universeFile: "testdata/npm/universe.yaml",
			vulnsFile:    "testdata/npm/vulnerabilities.yaml",
			manifestPath: "npm/vuln-without-fix/package.json",
			readWriter:   npmRW,
			opts:         options.DefaultRemediationOptions(),
			wantFile:     "testdata/npm/vuln-without-fix/patches.json",
		},
		{
			name:         "npm-diamond",
			universeFile: "testdata/npm/universe.yaml",
			vulnsFile:    "testdata/npm/vulnerabilities.yaml",
			manifestPath: "npm/diamond/package.json",
			readWriter:   npmRW,
			opts:         options.DefaultRemediationOptions(),
			wantFile:     "testdata/npm/diamond/patches.json",
		},
		{
			name:         "npm-removed-vuln-dep",
			universeFile: "testdata/npm/universe.yaml",
			vulnsFile:    "testdata/npm/vulnerabilities.yaml",
			manifestPath: "npm/removed-vuln/package.json",
			readWriter:   npmRW,
			opts:         options.DefaultRemediationOptions(),
			wantFile:     "testdata/npm/removed-vuln/patches.json",
		},
		{
			name:         "npm-introduced-vuln",
			universeFile: "testdata/npm/universe.yaml",
			vulnsFile:    "testdata/npm/vulnerabilities.yaml",
			manifestPath: "npm/introduce-vuln/package.json",
			readWriter:   npmRW,
			opts:         options.DefaultRemediationOptions(),
			wantFile:     "testdata/npm/introduce-vuln/patches.json",
		},
		{
			name:         "npm-non-constraining-dep",
			universeFile: "testdata/npm/universe.yaml",
			vulnsFile:    "testdata/npm/vulnerabilities.yaml",
			manifestPath: "npm/non-constraining/package.json",
			readWriter:   npmRW,
			opts:         options.DefaultRemediationOptions(),
			wantFile:     "testdata/npm/non-constraining/patches.json",
		},
		{
			name:         "npm-deepen-to-remediate",
			universeFile: "testdata/npm/universe.yaml",
			vulnsFile:    "testdata/npm/vulnerabilities.yaml",
			manifestPath: "npm/deepen/package.json",
			readWriter:   npmRW,
			opts: options.RemediationOptions{
				MaxDepth:      3,
				UpgradeConfig: upgrade.NewConfig(),
			},
			wantFile: "testdata/npm/deepen/patches.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantFile, err := os.Open(tt.wantFile)
			if err != nil {
				t.Fatalf("failed opening wantFile: %v", err)
			}
			defer wantFile.Close()
			var want []result.Patch
			if err := json.NewDecoder(wantFile).Decode(&want); err != nil {
				t.Fatalf("failed decoding wantFile: %v", err)
			}

			fsys := scalibrfs.DirFS("./testdata")
			m, err := tt.readWriter.Read(tt.manifestPath, fsys)
			if err != nil {
				t.Fatalf("failed reading manifest: %v", err)
			}

			cl := clienttest.NewMockResolutionClient(t, tt.universeFile)
			vm := matchertest.NewMockVulnerabilityMatcher(t, tt.vulnsFile)
			resolved, err := remediation.ResolveManifest(context.Background(), cl, vm, m, &tt.opts)
			if err != nil {
				t.Fatalf("failed resolving manifest: %v", err)
			}
			gotFull, err := relax.ComputePatches(context.Background(), cl, vm, resolved, &tt.opts)
			if err != nil {
				t.Fatalf("failed computing patches: %v", err)
			}
			got := gotFull.Patches

			// Type is not in exported to json, so just ignore it.
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty(), cmpopts.IgnoreTypes(dep.Type{})); diff != "" {
				t.Errorf("ComputePatches: unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
