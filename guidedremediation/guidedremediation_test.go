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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/guidedremediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/matchertest"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

func TestFixOverride(t *testing.T) {
	for _, tt := range []struct {
		name             string
		universeDir      string
		manifest         string
		wantManifestPath string
		wantResultPath   string
		remOpts          options.RemediationOptions
		maxUpgrades      int
		noIntroduce      bool
	}{
		{
			name:             "basic",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/basic/pom.xml",
			wantManifestPath: "testdata/maven/basic/want.pom.xml",
			wantResultPath:   "testdata/maven/basic/result.json",
			remOpts:          options.DefaultRemediationOptions(),
		},
		{
			name:             "patch choice",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/patchchoice/pom.xml",
			wantManifestPath: "testdata/maven/patchchoice/want.pom.xml",
			wantResultPath:   "testdata/maven/patchchoice/result.json",
			remOpts:          options.DefaultRemediationOptions(),
		},
		{
			name:             "max upgrades",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/patchchoice/pom.xml",
			wantManifestPath: "testdata/maven/maxupgrades/want.pom.xml",
			wantResultPath:   "testdata/maven/maxupgrades/result.json",
			remOpts:          options.DefaultRemediationOptions(),
			maxUpgrades:      2,
		},
		{
			name:        "no introduce",
			universeDir: "testdata/maven",
			// Using same testdata as maxUpgrades because the result happens to be the same.
			manifest:         "testdata/maven/patchchoice/pom.xml",
			wantManifestPath: "testdata/maven/maxupgrades/want.pom.xml",
			wantResultPath:   "testdata/maven/maxupgrades/result.json",
			remOpts:          options.DefaultRemediationOptions(),
			noIntroduce:      true,
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

			opts := options.FixVulnsOptions{
				Manifest:           manifestPath,
				Strategy:           strategy.StrategyOverride,
				MatcherClient:      matcher,
				ResolveClient:      client,
				RemediationOptions: tt.remOpts,
				MaxUpgrades:        tt.maxUpgrades,
				NoIntroduce:        tt.noIntroduce,
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
			if runtime.GOOS == "windows" {
				wantManifest = bytes.ReplaceAll(wantManifest, []byte("\r\n"), []byte("\n"))
				gotManifest = bytes.ReplaceAll(gotManifest, []byte("\r\n"), []byte("\n"))
			}

			if diff := cmp.Diff(wantManifest, gotManifest); diff != "" {
				t.Errorf("FixVulns() manifest mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFixInPlace(t *testing.T) {
	// Set up a test registry, since the lockfile writer needs to talk to the registry to get the package metadata.
	srv := clienttest.NewMockHTTPServer(t)
	srv.SetResponse(t, "/baz/1.0.1", []byte(`{
	"name": "baz",
	"version": "1.0.1",
	"dist": {
		"integrity": "sha512-aaaaaaaaaaaa",
		"tarball": "https://registry.npmjs.org/baz/-/baz-1.0.1.tgz"
	}
}
`))
	srv.SetResponse(t, "/baz/2.0.1", []byte(`{
	"name": "baz",
	"version": "2.0.1",
	"dist": {
		"integrity": "sha512-bbbbbbbbbbbb",
		"tarball": "https://registry.npmjs.org/baz/-/baz-2.0.1.tgz"
	}
}
`))
	for _, tt := range []struct {
		name             string
		universeDir      string
		lockfile         string
		wantLockfilePath string
		wantResultPath   string
		remOpts          options.RemediationOptions
		maxUpgrades      int
		noIntroduce      bool
	}{
		{
			name:             "basic",
			universeDir:      "testdata/npm",
			lockfile:         "testdata/npm/basic/package-lock.json",
			wantLockfilePath: "testdata/npm/basic/want.package-lock.json",
			wantResultPath:   "testdata/npm/basic/result.json",
			remOpts:          options.DefaultRemediationOptions(),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := clienttest.NewMockResolutionClient(t, filepath.Join(tt.universeDir, "universe.yaml"))
			matcher := matchertest.NewMockVulnerabilityMatcher(t, filepath.Join(tt.universeDir, "vulnerabilities.yaml"))

			tmpDir := t.TempDir()
			lockfilePath := filepath.Join(tmpDir, "package-lock.json")
			data, err := os.ReadFile(tt.lockfile)
			if err != nil {
				t.Fatalf("failed reading lockfile for copy: %v", err)
			}
			if err := os.WriteFile(lockfilePath, data, 0644); err != nil {
				t.Fatalf("failed copying lockfile: %v", err)
			}

			// make a npmrc to talk to test registry
			if err := os.WriteFile(filepath.Join(tmpDir, ".npmrc"), []byte("registry="+srv.URL+"\n"), 0644); err != nil {
				t.Fatalf("failed creating npmrc: %v", err)
			}

			opts := options.FixVulnsOptions{
				Lockfile:           lockfilePath,
				Strategy:           strategy.StrategyInPlace,
				MatcherClient:      matcher,
				ResolveClient:      client,
				RemediationOptions: tt.remOpts,
				MaxUpgrades:        tt.maxUpgrades,
				NoIntroduce:        tt.noIntroduce,
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

			wantLockfile, err := os.ReadFile(tt.wantLockfilePath)
			if err != nil {
				t.Fatalf("failed reading want lockfile for comparison: %v", err)
			}
			gotLockfile, err := os.ReadFile(lockfilePath)
			if err != nil {
				t.Fatalf("failed reading got lockfile for comparison: %v", err)
			}

			if diff := cmp.Diff(wantLockfile, gotLockfile); diff != "" {
				t.Errorf("FixVulns() lockfile mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	for _, tt := range []struct {
		name             string
		universeDir      string
		manifest         string
		parentManifest   string
		wantManifestPath string
		wantResultPath   string
		config           upgrade.Config
		ignoreDev        bool
	}{
		{
			name:             "basic",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/update/pom.xml",
			parentManifest:   "testdata/maven/update/parent.xml",
			wantManifestPath: "testdata/maven/update/want.basic.pom.xml",
			wantResultPath:   "testdata/maven/update/want.basic.json",
		},
		{
			name:             "upgrade config",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/update/pom.xml",
			parentManifest:   "testdata/maven/update/parent.xml",
			wantManifestPath: "testdata/maven/update/want.config.pom.xml",
			wantResultPath:   "testdata/maven/update/want.config.json",
			config: upgrade.Config{
				"pkg:e": upgrade.Minor,
			},
		},
		{
			name:             "ignore dev",
			universeDir:      "testdata/maven",
			manifest:         "testdata/maven/update/pom.xml",
			parentManifest:   "testdata/maven/update/parent.xml",
			wantManifestPath: "testdata/maven/update/want.dev.pom.xml",
			wantResultPath:   "testdata/maven/update/want.dev.json",
			ignoreDev:        true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := clienttest.NewMockResolutionClient(t, filepath.Join(tt.universeDir, "universe.yaml"))

			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "pom.xml")
			data, err := os.ReadFile(tt.manifest)
			if err != nil {
				t.Fatalf("failed reading manifest for copy: %v", err)
			}
			if err := os.WriteFile(manifestPath, data, 0644); err != nil {
				t.Fatalf("failed copying manifest: %v", err)
			}

			parentPath := filepath.Join(tmpDir, "parent.xml")
			data, err = os.ReadFile(tt.parentManifest)
			if err != nil {
				t.Fatalf("failed reading manifest for copy: %v", err)
			}
			if err = os.WriteFile(parentPath, data, 0644); err != nil {
				t.Fatalf("failed copying manifest: %v", err)
			}

			opts := options.UpdateOptions{
				Manifest:      manifestPath,
				ResolveClient: client,
				UpgradeConfig: tt.config,
				IgnoreDev:     tt.ignoreDev,
			}

			gotRes, err := guidedremediation.Update(opts)
			if err != nil {
				t.Fatalf("failed to update: %v", err)
			}

			wantManifest, err := os.ReadFile(tt.wantManifestPath)
			if err != nil {
				t.Fatalf("failed reading want manifest for comparison: %v", err)
			}
			gotManifest, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("failed reading got manifest for comparison: %v", err)
			}
			if runtime.GOOS == "windows" {
				wantManifest = bytes.ReplaceAll(wantManifest, []byte("\r\n"), []byte("\n"))
				gotManifest = bytes.ReplaceAll(gotManifest, []byte("\r\n"), []byte("\n"))
			}
			if diff := cmp.Diff(wantManifest, gotManifest); diff != "" {
				t.Errorf("Update() manifest mismatch (-want +got):\n%s", diff)
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
				t.Errorf("Update() result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
