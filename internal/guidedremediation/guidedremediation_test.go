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

package guidedremediation_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/internal/guidedremediation"
	"github.com/google/osv-scalibr/internal/guidedremediation/matchertest"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation/result"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation/strategy"
)

func TestFixOverride(t *testing.T) {
	for _, tt := range []struct {
		name             string
		universeDir      string
		manifest         string
		wantManifestPath string
		wantResultPath   string
		remOpts          remediation.Options
		maxUpgrades      int
	}{
		{
			name:             "basic",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/basic/pom.xml",
			wantManifestPath: "testdata/maven/basic/want.pom.xml",
			wantResultPath:   "testdata/maven/basic/result.json",
			remOpts:          *remediation.DefaultOptions(),
		},
		{
			name:             "patch choice",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/patchchoice/pom.xml",
			wantManifestPath: "testdata/maven/patchchoice/want.pom.xml",
			wantResultPath:   "testdata/maven/patchchoice/result.json",
			remOpts:          *remediation.DefaultOptions(),
		},
		{
			name:             "max upgrades",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/maxupgrades/pom.xml",
			wantManifestPath: "testdata/maven/maxupgrades/want.pom.xml",
			wantResultPath:   "testdata/maven/maxupgrades/result.json",
			remOpts:          *remediation.DefaultOptions(),
			maxUpgrades:      2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := clienttest.NewMockResolutionClient(t, filepath.Join(tt.universeDir, "universe.yaml"))
			matcher := matchertest.NewMockVulnerabilityMatcher(t, filepath.Join(tt.universeDir, "vulnerabilities.yaml"))

			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "pom.xml")
			data, err := os.ReadFile(tt.manifest)
			if err != nil {
				t.Fatalf("failed reading manifest for copy: %v", err)
			}
			if err := os.WriteFile(manifestPath, data, 0644); err != nil {
				t.Fatalf("failed copying manifest: %v", err)
			}

			opts := guidedremediation.RemediationOptions{
				Manifest:      manifestPath,
				Strategy:      strategy.StrategyOverride,
				MatcherClient: matcher,
				ResolveClient: client,
				RemOpts:       tt.remOpts,
				MaxUpgrades:   tt.maxUpgrades,
			}

			gotRes, err := guidedremediation.FixVulns(opts)
			if err != nil {
				t.Fatalf("error fixing vulns: %v", err)
			}
			var wantRes result.Result
			f, err := os.Open(tt.wantResultPath)
			if err != nil {
				t.Fatalf("failed opening result file: %v", err)
			}
			defer f.Close()
			if err := json.NewDecoder(f).Decode(&wantRes); err != nil {
				t.Fatalf("failed decoding result file: %v", err)
			}
			diffOpts := []cmp.Option{
				cmpopts.IgnoreFields(result.Result{}, "Path"),
				cmpopts.IgnoreFields(result.PackageUpdate{}, "Type"),
			}
			if diff := cmp.Diff(wantRes, gotRes, diffOpts...); diff != "" {
				t.Errorf("FixVulns() result mismatch (-want +got):\n%s", diff)
			}

			wantManifest, err := os.ReadFile(tt.wantManifestPath)
			if err != nil {
				t.Fatalf("failed reading want manifest for comparison: %v", err)
			}
			gotManifest, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("failed reading got manifest for comparison: %v", err)
			}

			if diff := cmp.Diff(wantManifest, gotManifest); diff != "" {
				t.Errorf("FixVulns() manifest mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
