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

//go:build integration
// +build integration

package javascript_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/javascript"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func corpusPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "testdata", "corpus.json")
}

func fixturePath(t *testing.T, cve, sub string) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Join(wd, "testdata", cve, sub)
}

func runEnricher(t *testing.T, root string, vulns []*inventory.PackageVuln) []*inventory.PackageVuln {
	t.Helper()
	e := javascript.NewWithConfig(javascript.Config{
		MetadataFile:   corpusPath(t),
		SubprojectRoot: root,
	})
	inv := &inventory.Inventory{PackageVulns: vulns}
	if err := e.Enrich(context.Background(), nil, inv); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	return inv.PackageVulns
}

func TestIntegration_GHSAfv66_Positive(t *testing.T) {
	root := fixturePath(t, "GHSA-fv66-9v8q-g76r", "positive")
	if _, err := os.Stat(filepath.Join(root, "node_modules")); err != nil {
		t.Skipf("node_modules missing in %s; run `pnpm install` first", root)
	}
	vulns := []*inventory.PackageVuln{{
		Vulnerability: &osvpb.Vulnerability{Id: "GHSA-fv66-9v8q-g76r"},
		Package:       &extractor.Package{Name: "react-server-dom-webpack", Version: "19.2.0"},
	}}
	out := runEnricher(t, root, vulns)
	if len(out[0].ExploitabilitySignals) != 0 {
		t.Errorf("positive: want 0 signals (reachable), got %d", len(out[0].ExploitabilitySignals))
	}
}

func TestIntegration_GHSAfv66_Negative(t *testing.T) {
	root := fixturePath(t, "GHSA-fv66-9v8q-g76r", "negative")
	if _, err := os.Stat(filepath.Join(root, "node_modules")); err != nil {
		t.Skipf("node_modules missing in %s; run `pnpm install` first", root)
	}
	vulns := []*inventory.PackageVuln{{
		Vulnerability: &osvpb.Vulnerability{Id: "GHSA-fv66-9v8q-g76r"},
		Package:       &extractor.Package{Name: "react-server-dom-webpack", Version: "19.2.0"},
	}}
	out := runEnricher(t, root, vulns)
	sigs := out[0].ExploitabilitySignals
	if len(sigs) != 1 {
		t.Fatalf("negative: want 1 signal (unreachable), got %d", len(sigs))
	}
	if sigs[0].Justification != vex.VulnerableCodeNotInExecutePath {
		t.Errorf("justification = %v, want VulnerableCodeNotInExecutePath", sigs[0].Justification)
	}
}

func TestIntegration_GHSAj5w5_Positive(t *testing.T) {
	root := fixturePath(t, "GHSA-j5w5-568x-rq53", "positive")
	if _, err := os.Stat(filepath.Join(root, "node_modules")); err != nil {
		t.Skipf("node_modules missing in %s; run `pnpm install` first", root)
	}
	vulns := []*inventory.PackageVuln{{
		Vulnerability: &osvpb.Vulnerability{Id: "GHSA-j5w5-568x-rq53"},
		Package:       &extractor.Package{Name: "@evomap/evolver"},
	}}
	out := runEnricher(t, root, vulns)
	if len(out[0].ExploitabilitySignals) != 0 {
		t.Errorf("positive: want 0 signals, got %d", len(out[0].ExploitabilitySignals))
	}
}

func TestIntegration_GHSAj5w5_Negative(t *testing.T) {
	root := fixturePath(t, "GHSA-j5w5-568x-rq53", "negative")
	if _, err := os.Stat(filepath.Join(root, "node_modules")); err != nil {
		t.Skipf("node_modules missing in %s; run `pnpm install` first", root)
	}
	vulns := []*inventory.PackageVuln{{
		Vulnerability: &osvpb.Vulnerability{Id: "GHSA-j5w5-568x-rq53"},
		Package:       &extractor.Package{Name: "@evomap/evolver"},
	}}
	out := runEnricher(t, root, vulns)
	sigs := out[0].ExploitabilitySignals
	if len(sigs) != 1 {
		t.Fatalf("negative: want 1 signal, got %d", len(sigs))
	}
	if sigs[0].Justification != vex.VulnerableCodeNotInExecutePath {
		t.Errorf("wrong justification: %v", sigs[0].Justification)
	}
}

