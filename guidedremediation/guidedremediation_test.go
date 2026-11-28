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

package guidedremediation

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/guidedremediation/internal/vulnenrichertest"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

func TestFixOverride(t *testing.T) {
	for _, tt := range []struct {
		name              string
		universeDir       string
		manifest          string
		wantManifestPath  string
		wantResultPath    string
		remOpts           options.RemediationOptions
		maxUpgrades       int
		noIntroduce       bool
		noMavenNewDepMgmt bool
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
		{
			name:              "no new dependency management",
			universeDir:       "testdata/maven",
			manifest:          "testdata/maven/patchchoice/pom.xml",
			wantManifestPath:  "testdata/maven/nodepmgmt/want.pom.xml",
			wantResultPath:    "testdata/maven/nodepmgmt/result.json",
			remOpts:           options.DefaultRemediationOptions(),
			noMavenNewDepMgmt: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// mavenClient is not used in the test, but is required to be non-nil for pom.xml manifests.
			mavenClient, _ := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), "")
			client := clienttest.NewMockResolutionClient(t, filepath.Join(tt.universeDir, "universe.yaml"))
			enricher := vulnenrichertest.NewMockVulnerabilityEnricher(t, filepath.Join(tt.universeDir, "vulnerabilities.json"))

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
				VulnEnricher:       enricher,
				ResolveClient:      client,
				MavenClient:        mavenClient,
				RemediationOptions: tt.remOpts,
				MaxUpgrades:        tt.maxUpgrades,
				NoIntroduce:        tt.noIntroduce,
				NoMavenNewDepMgmt:  tt.noMavenNewDepMgmt,
			}

			gotRes, err := FixVulns(opts)
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

func TestFixRelax(t *testing.T) {
	for _, tt := range []struct {
		name             string
		universeDir      string
		manifest         string
		lockfile         string
		wantManifestPath string
		wantResultPath   string
		remOpts          options.RemediationOptions
		maxUpgrades      int
		noIntroduce      bool
	}{
		{
			name:             "npm basic",
			universeDir:      "testdata/npm",
			manifest:         "testdata/npm/basicrelax/package.json",
			lockfile:         "testdata/npm/basicrelax/package-lock.json",
			wantManifestPath: "testdata/npm/basicrelax/want.package.json",
			wantResultPath:   "testdata/npm/basicrelax/result.json",
			remOpts:          options.DefaultRemediationOptions(),
		},
		{
			name:             "python requirements",
			universeDir:      "testdata/python",
			manifest:         "testdata/python/relax/requirements/requirements.txt",
			wantManifestPath: "testdata/python/relax/requirements/want.requirements.txt",
			wantResultPath:   "testdata/python/relax/requirements/result.json",
			remOpts:          options.DefaultRemediationOptions(),
		},
		{
			name:             "python poetry",
			universeDir:      "testdata/python",
			manifest:         "testdata/python/relax/poetry/pyproject.toml",
			wantManifestPath: "testdata/python/relax/poetry/want.pyproject.toml",
			wantResultPath:   "testdata/python/relax/poetry/result.json",
			remOpts:          options.DefaultRemediationOptions(),
		},
		{
			name:             "python pipfile",
			universeDir:      "testdata/python",
			manifest:         "testdata/python/relax/pipfile/Pipfile",
			wantManifestPath: "testdata/python/relax/pipfile/want.Pipfile",
			wantResultPath:   "testdata/python/relax/pipfile/result.json",
			remOpts:          options.DefaultRemediationOptions(),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := clienttest.NewMockResolutionClient(t, filepath.Join(tt.universeDir, "universe.yaml"))
			enricher := vulnenrichertest.NewMockVulnerabilityEnricher(t, filepath.Join(tt.universeDir, "vulnerabilities.json"))

			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, filepath.Base(tt.manifest))
			data, err := os.ReadFile(tt.manifest)
			if err != nil {
				t.Fatalf("failed reading manifest for copy: %v", err)
			}
			if err := os.WriteFile(manifestPath, data, 0644); err != nil {
				t.Fatalf("failed copying manifest: %v", err)
			}

			var lockfilePath string
			if tt.lockfile != "" {
				lockfilePath = filepath.Join(tmpDir, filepath.Base(tt.lockfile))
				data, err := os.ReadFile(tt.lockfile)
				if err != nil {
					t.Fatalf("failed reading lockfile for copy: %v", err)
				}
				if err := os.WriteFile(lockfilePath, data, 0644); err != nil {
					t.Fatalf("failed copying lockfile: %v", err)
				}
			}

			opts := options.FixVulnsOptions{
				Manifest:           manifestPath,
				Lockfile:           lockfilePath,
				Strategy:           strategy.StrategyRelax,
				VulnEnricher:       enricher,
				ResolveClient:      client,
				RemediationOptions: tt.remOpts,
				MaxUpgrades:        tt.maxUpgrades,
				NoIntroduce:        tt.noIntroduce,
			}

			gotRes, err := FixVulns(opts)
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
			enricher := vulnenrichertest.NewMockVulnerabilityEnricher(t, filepath.Join(tt.universeDir, "vulnerabilities.json"))

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
				VulnEnricher:       enricher,
				ResolveClient:      client,
				RemediationOptions: tt.remOpts,
				MaxUpgrades:        tt.maxUpgrades,
				NoIntroduce:        tt.noIntroduce,
			}

			gotRes, err := FixVulns(opts)
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
			// mavenClient is not used in the test, but is required to be non-nil for pom.xml manifests.
			mavenClient, _ := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), "")
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
				MavenClient:   mavenClient,
				UpgradeConfig: tt.config,
				IgnoreDev:     tt.ignoreDev,
			}

			gotRes, err := Update(opts)
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

func TestCheckUnsafeLockfileGenerationEnabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     options.FixVulnsOptions
		wantDeny bool
	}{
		{"pip_denied", options.FixVulnsOptions{Manifest: "requirements.in", Lockfile: "requirements.txt"}, true},
		{"poetry_denied", options.FixVulnsOptions{Manifest: "pyproject.toml", Lockfile: "poetry.lock"}, true},
		{"pipenv_denied", options.FixVulnsOptions{Manifest: "Pipfile", Lockfile: "Pipfile.lock"}, true},
		{"pip_allowed", options.FixVulnsOptions{Manifest: "requirements.in", Lockfile: "requirements.txt", AllowUnsafeExecution: true}, false},
		{"manifest_only", options.FixVulnsOptions{Manifest: "requirements.in"}, false},
		{"lockfile_only", options.FixVulnsOptions{Lockfile: "requirements.txt"}, false},
		{"mismatched_pair", options.FixVulnsOptions{Manifest: "requirements.in", Lockfile: "other.txt"}, false},
		{"npm", options.FixVulnsOptions{Manifest: "package.json", Lockfile: "package-lock.json"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkUnsafeLockfileGenerationEnabled(tc.opts)
			if tc.wantDeny {
				if err == nil || !strings.Contains(err.Error(), "set AllowUnsafeExecution to true") {
					t.Fatalf("checkUnsafeLockfileGenerationEnabled() = %v, want unsafe execution error", err)
				}
			} else if err != nil {
				t.Fatalf("checkUnsafeLockfileGenerationEnabled() = %v, want nil", err)
			}
		})
	}
}

func TestFixVulnsRejectsUnsafePythonBeforeWrites(t *testing.T) {
	enricher := vulnenrichertest.NewMockVulnerabilityEnricher(t, "testdata/python/vulnerabilities.json")
	for _, tc := range []struct{ manifest, lockfile string }{
		{"requirements.in", "requirements.txt"},
		{"pyproject.toml", "poetry.lock"},
		{"Pipfile", "Pipfile.lock"},
	} {
		t.Run(tc.manifest, func(t *testing.T) {
			dir := t.TempDir()
			manifest := filepath.Join(dir, tc.manifest)
			lockfile := filepath.Join(dir, tc.lockfile)
			for _, path := range []string{manifest, lockfile} {
				if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Nil resolution clients and invalid file contents also ensure that
			// permission is checked before parsing or dependency resolution.
			_, err := FixVulns(options.FixVulnsOptions{
				Manifest: manifest, Lockfile: lockfile, VulnEnricher: enricher,
			})
			if err == nil || !strings.Contains(err.Error(), "set AllowUnsafeExecution to true") {
				t.Fatalf("FixVulns() = %v, want unsafe execution error", err)
			}
			for _, path := range []string{manifest, lockfile} {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != "unchanged" {
					t.Errorf("file %q modified: %q", path, data)
				}
			}
		})
	}
}

func TestPythonLockfileCommands(t *testing.T) {
	for _, tc := range []struct{ manifest, executable, args string }{
		{"requirements.in", "pip-compile", "--generate-hashes\nrequirements.in\n"},
		{"pyproject.toml", "poetry", "lock\n"},
		{"Pipfile", "pipenv", "lock\n"},
	} {
		t.Run(tc.executable, func(t *testing.T) {
			dir, record := fakeLockfileTool(t, tc.executable, false)
			if err := writeLockfileFromManifest(context.Background(), filepath.Join(dir, tc.manifest)); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(data), dir+"\n"+tc.args; got != want {
				t.Errorf("tool invocation = %q, want %q", got, want)
			}
		})
	}
}

func TestFixVulnsPythonUnsafeOptIn(t *testing.T) {
	dir, record := fakeLockfileTool(t, "pip-compile", false)
	manifest := filepath.Join(dir, "requirements.in")
	data, err := os.ReadFile("testdata/python/relax/requirements/requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	lockfile := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(lockfile, data, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = FixVulns(options.FixVulnsOptions{
		Manifest:             manifest,
		Lockfile:             lockfile,
		AllowUnsafeExecution: true,
		ResolveClient:        clienttest.NewMockResolutionClient(t, "testdata/python/universe.yaml"),
		VulnEnricher:         vulnenrichertest.NewMockVulnerabilityEnricher(t, "testdata/python/vulnerabilities.json"),
		RemediationOptions:   options.DefaultRemediationOptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(record)
	if err != nil {
		t.Fatalf("pip-compile was not invoked: %v", err)
	}
	if want := dir + "\n--generate-hashes\nrequirements.in\n"; string(data) != want {
		t.Errorf("pip-compile invocation = %q, want %q", data, want)
	}
}

func TestNpmLockfileDisablesScripts(t *testing.T) {
	for _, retry := range []bool{false, true} {
		name := "first_attempt"
		if retry {
			name = "retry"
		}
		t.Run(name, func(t *testing.T) {
			dir, record := fakeLockfileTool(t, "npm", retry)
			if err := writeLockfileFromManifest(context.Background(), filepath.Join(dir, "package.json")); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			want := dir + "\ninstall\n--package-lock-only\n--ignore-scripts\n"
			if retry {
				want += dir + "\ninstall\n--package-lock-only\n--legacy-peer-deps\n--ignore-scripts\n"
			}
			if string(data) != want {
				t.Errorf("npm invocation = %q, want %q", data, want)
			}
		})
	}
}

// fakeLockfileTool records invocations without accessing dependencies or registries.
func fakeLockfileTool(t *testing.T, executable string, failFirst bool) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake package manager requires a POSIX shell")
	}
	dir := t.TempDir()
	bin := t.TempDir()
	record := filepath.Join(t.TempDir(), "invocations")
	script := "#!/bin/sh\n"
	if failFirst {
		script += "if [ ! -f \"$SCALIBR_TEST_RECORD\" ]; then\n" +
			"  printf '%s\\n' \"$PWD\" \"$@\" >> \"$SCALIBR_TEST_RECORD\"\n  exit 1\nfi\n"
	}
	script += "printf '%s\\n' \"$PWD\" \"$@\" >> \"$SCALIBR_TEST_RECORD\"\n"
	if err := os.WriteFile(filepath.Join(bin, executable), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("SCALIBR_TEST_RECORD", record)
	// Resolve symlinks so that the shell's physical working directory agrees
	// with expectations on platforms where the temporary directory is a link.
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, record
}
