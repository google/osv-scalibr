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

// Package source provides an enricher that uses govulncheck to scan Go source code.
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/govulncheck/source/internal"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/vuln/scan"
)

const (
	// Name is the unique name of this enricher.
	Name = "reachability/go/source"
)

// ErrNoGoToolchain is returned when the go toolchain is not found in the system.
var ErrNoGoToolchain = errors.New("no Go toolchain found")

// Enricher is an enricher that runs govulncheck on Go source code.
type Enricher struct {
	offlineVulnDBPath string
}

// Name returns the name of the enricher.
func (e *Enricher) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (e *Enricher) Version() int {
	return 0
}

// Requirements returns the requirements of the enricher.
func (e *Enricher) Requirements() *plugin.Capabilities {
	var network plugin.Network
	if e.offlineVulnDBPath != "" {
		network = plugin.NetworkOffline
	} else {
		network = plugin.NetworkOnline
	}

	return &plugin.Capabilities{
		Network:       network,
		DirectFS:      true,
		RunningSystem: true,
	}
}

// RequiredPlugins returns the names of the plugins required by this enricher.
func (e *Enricher) RequiredPlugins() []string {
	return []string{gomod.Name}
}

// Enrich runs govulncheck on the Go modules in the inventory.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	cmd := exec.CommandContext(ctx, "go", "version")
	_, err := cmd.Output()
	if err != nil {
		return ErrNoGoToolchain
	}

	goModVersions := make(map[string]string)
	for _, pkg := range inv.Packages {
		if !slices.Contains(pkg.Plugins, gomod.Name) {
			continue
		}
		if pkg.Name == "stdlib" {
			for _, l := range pkg.Locations {
				if goModVersions[l] != "" {
					continue
				}

				// Set GOVERSION to the Go version in go.mod.
				goModVersions[l] = pkg.Version

				continue
			}
		}
	}

	for goModLocation, goVersion := range goModVersions {
		modDir := filepath.Dir(goModLocation)
		absModDir := filepath.Join(input.ScanRoot.Path, modDir)
		findings, err := e.runGovulncheck(ctx, absModDir, goVersion)
		if err != nil {
			log.Errorf("govulncheck on %s: %v", modDir, err)
			continue
		}

		if len(findings) == 0 {
			continue
		}

		e.addSignals(inv, findings)
	}

	return nil
}

func (e *Enricher) addSignals(inv *inventory.Inventory, idToFindings map[string][]*internal.Finding) {
	for _, pv := range inv.PackageVulns {
		findings, exist := idToFindings[pv.Vulnerability.Id]

		if !exist {
			// The finding doesn't exist, this could mean two things:
			// 1. The code does not import the vulnerable package.
			// 2. The vulnerability does not have symbol information, so govulncheck ignored it.
			if vulnHasImportsField(pv.Vulnerability, pv.Package) {
				// If there is symbol information, then analysis has been performed.
				// Since this finding doesn't exist, it means the code does not import the vulnerable package,
				// so definitely not called.
				pv.ExploitabilitySignals = append(pv.ExploitabilitySignals, &vex.FindingExploitabilitySignal{
					Plugin:        Name,
					Justification: vex.VulnerableCodeNotInExecutePath,
				})
			}

			// Otherwise, we don't know if the code is reachable or not.
			continue
		}

		// For entries with findings, check if the code is reachable or not by whether there is a trace.
		reachable := false
		for _, f := range findings {
			if len(f.Trace) > 0 && f.Trace[0].Function != "" {
				reachable = true
				break
			}
		}

		if !reachable {
			pv.ExploitabilitySignals = append(pv.ExploitabilitySignals, &vex.FindingExploitabilitySignal{
				Plugin:        Name,
				Justification: vex.VulnerableCodeNotInExecutePath,
			})
		}
	}
}

func (e *Enricher) runGovulncheck(ctx context.Context, absModDir string, goVersion string) (map[string][]*internal.Finding, error) {
	args := []string{"-C", absModDir, "-format", "json", "-mode", "source"}
	if e.offlineVulnDBPath != "" {
		args = append(args, "-db=file://"+e.offlineVulnDBPath)
	}
	cmd := scan.Command(ctx, append(args, "./...")...)
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Env = append(os.Environ(), "GOVERSION=go"+goVersion)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	// Group the output of govulncheck based on the OSV ID.
	h := &osvHandler{
		idToFindings: map[string][]*internal.Finding{},
	}
	if err := handleJSON(bytes.NewReader(b.Bytes()), h); err != nil {
		return nil, err
	}

	return h.idToFindings, nil
}

type osvHandler struct {
	idToFindings map[string][]*internal.Finding
}

func (h *osvHandler) Finding(f *internal.Finding) {
	h.idToFindings[f.OSV] = append(h.idToFindings[f.OSV], f)
}

func handleJSON(from io.Reader, to *osvHandler) error {
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := internal.Message{}
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		if msg.Finding != nil {
			to.Finding(msg.Finding)
		}
	}

	return nil
}

func vulnHasImportsField(vuln *osvschema.Vulnerability, pkg *extractor.Package) bool {
	for _, affected := range vuln.Affected {
		if pkg != nil {
			// TODO(#1559): Compare versions to see if this is the correct affected element
			// This is very unlikely to ever matter however.
			if affected.Package.Name != pkg.Name {
				continue
			}
		}
		_, hasImportsField := affected.EcosystemSpecific.GetFields()["imports"]
		if hasImportsField {
			return true
		}
	}

	return false
}

// New returns a new govulncheck source enricher.
func New(cfg *cpb.PluginConfig) enricher.Enricher {
	e := &Enricher{}
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.GovulncheckConfig { return c.GetGovulncheck() })
	if specific != nil {
		e.offlineVulnDBPath = specific.OfflineVulnDbPath
	}
	return e
}
