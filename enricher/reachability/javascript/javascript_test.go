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

package javascript_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/javascript"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/jelly"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestEnrich_NoOpWhenJellyUnavailable(t *testing.T) {
	// With an empty config, MetadataFile is unset → we skip cleanly.
	e := javascript.NewWithConfig(javascript.Config{
		MetadataFile: "", // unset: skip
	})
	inv := &inventory.Inventory{
		PackageVulns: []*inventory.PackageVuln{
			{
				Vulnerability: &osvpb.Vulnerability{Id: "GHSA-x"},
				Package:       &extractor.Package{Name: "lodash"},
			},
		},
	}
	if err := e.Enrich(context.Background(), nil, inv); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(inv.PackageVulns[0].ExploitabilitySignals) != 0 {
		t.Errorf("expected no signals on skip, got %d", len(inv.PackageVulns[0].ExploitabilitySignals))
	}
}

func TestEnrich_EmitsSignalOnUnreachable(t *testing.T) {
	corpusPath := writeCorpus(t, `[
	  {"osv":{"id":"GHSA-unreach","affected":[{"package":{"ecosystem":"npm","name":"lodash"}}]},"patterns":["call <lodash>.template"]}
	]`)
	proj := t.TempDir()
	// Install a stub lodash package in node_modules so depgraph.Build sees
	// it as on-disk; otherwise the enricher would (correctly) skip the
	// vuln as "package not installed" and emit no signal.
	installStubPkg(t, proj, "lodash", "4.17.21")
	mockJelly := &jelly.MockClient{
		AvailableResult: true,
		ImportResult: jelly.ImportResult{
			ReachablePackages: []jelly.ReachablePackage{{Name: "lodash"}},
		},
		FullScanResults: []jelly.ScanResult{
			{Matches: map[string][]string{"GHSA-unreach": {}}}, // analyzed, no matches
		},
	}
	e := javascript.NewWithConfigAndClient(javascript.Config{
		MetadataFile:   corpusPath,
		SubprojectRoot: proj,
	}, mockJelly)

	inv := &inventory.Inventory{
		PackageVulns: []*inventory.PackageVuln{{
			Vulnerability: &osvpb.Vulnerability{Id: "GHSA-unreach"},
			Package:       &extractor.Package{Name: "lodash", Version: "4.17.21"},
		}},
	}
	if err := e.Enrich(context.Background(), nil, inv); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	sigs := inv.PackageVulns[0].ExploitabilitySignals
	if len(sigs) != 1 {
		t.Fatalf("want 1 signal, got %d", len(sigs))
	}
	if sigs[0].Justification != vex.VulnerableCodeNotInExecutePath {
		t.Errorf("justification = %v, want VulnerableCodeNotInExecutePath", sigs[0].Justification)
	}
}

func TestEnrich_NoSignalOnReachable(t *testing.T) {
	corpusPath := writeCorpus(t, `[
	  {"osv":{"id":"GHSA-reach","affected":[{"package":{"ecosystem":"npm","name":"lodash"}}]},"patterns":["call <lodash>.template"]}
	]`)
	proj := t.TempDir()
	installStubPkg(t, proj, "lodash", "4.17.21")
	mockJelly := &jelly.MockClient{
		AvailableResult: true,
		ImportResult: jelly.ImportResult{
			ReachablePackages: []jelly.ReachablePackage{{Name: "lodash"}},
		},
		FullScanResults: []jelly.ScanResult{
			{Matches: map[string][]string{"GHSA-reach": {"app.js:1:1:1:2"}}},
		},
	}
	e := javascript.NewWithConfigAndClient(javascript.Config{
		MetadataFile:   corpusPath,
		SubprojectRoot: proj,
	}, mockJelly)
	inv := &inventory.Inventory{
		PackageVulns: []*inventory.PackageVuln{{
			Vulnerability: &osvpb.Vulnerability{Id: "GHSA-reach"},
			Package:       &extractor.Package{Name: "lodash", Version: "4.17.21"},
		}},
	}
	if err := e.Enrich(context.Background(), nil, inv); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(inv.PackageVulns[0].ExploitabilitySignals) != 0 {
		t.Errorf("reachable vuln should emit no signal; got %d", len(inv.PackageVulns[0].ExploitabilitySignals))
	}
}

func writeCorpus(t *testing.T, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// installStubPkg writes a minimal valid package.json under
// <proj>/node_modules/<name>/ so depgraph.Build records it as on-disk,
// AND writes a root <proj>/package.json that declares the package as a
// direct dependency so PathsToLeaf actually finds the leaf via a root.
// Without the root declaration the leaf is "orphan in graph" — present
// but unreachable from any root — and the enricher correctly skips it.
func installStubPkg(t *testing.T, proj, name, version string) {
	t.Helper()
	dir := filepath.Join(proj, "node_modules", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pj := `{"name":"` + name + `","version":"` + version + `"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pj), 0o600); err != nil {
		t.Fatal(err)
	}
	// Root package.json declaring this package as a dep, so depgraph
	// treats it as reachable from a root rather than an orphan.
	rootPJ := `{"name":"testapp","version":"0.0.0","dependencies":{"` + name + `":"^` + version + `"}}`
	_ = os.WriteFile(filepath.Join(proj, "package.json"), []byte(rootPJ), 0o600)
}
