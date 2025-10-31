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

package inplace_test

import (
	"encoding/json"
	"os"
	"testing"

	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile/npm"
	"github.com/google/osv-scalibr/guidedremediation/internal/matchertest"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/inplace"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

func TestComputePatches(t *testing.T) {
	npmWR, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("failed getting ReadWriter: %v", err)
	}
	tests := []struct {
		name         string
		universeFile string
		vulnsFile    string
		lockfilePath string
		readWriter   lockfile.ReadWriter
		opts         options.RemediationOptions
		wantFile     string
	}{
		{
			name:         "npm",
			universeFile: "testdata/npm/universe.yaml",
			vulnsFile:    "testdata/npm/vulnerabilities.json",
			lockfilePath: "npm/package-lock.json",
			readWriter:   npmWR,
			opts:         options.DefaultRemediationOptions(),
			wantFile:     "testdata/npm/patches.json",
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
			g, err := tt.readWriter.Read(tt.lockfilePath, fsys)
			if err != nil {
				t.Fatalf("failed reading graph: %v", err)
			}

			cl := clienttest.NewMockResolutionClient(t, tt.universeFile)
			vm := matchertest.NewMockVulnerabilityMatcher(t, tt.vulnsFile)
			resolvedGraph, err := remediation.ResolveGraphVulns(t.Context(), cl, vm, g, nil, &tt.opts)
			if err != nil {
				t.Fatalf("failed resolving vulns from graph: %v", err)
			}

			got, err := inplace.ComputePatches(t.Context(), cl, resolvedGraph, &tt.opts)
			if err != nil {
				t.Fatalf("failed computing patches: %v", err)
			}
			// Type is not in exported to json, so just ignore it.
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty(), cmpopts.IgnoreTypes(dep.Type{})); diff != "" {
				t.Errorf("ComputePatches: unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
