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

// Package binary implements a detector that uses govulncheck to scan for vulns on Go binaries found
// on the filesystem.
package binary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/vuln/scan"
)

const (
	// Name is the unique name of this detector.
	Name = "govulncheck/binary"
)

// Detector is a SCALIBR Detector that uses govulncheck to scan for vulns on Go binaries found
// on the filesystem.
type Detector struct {
	OfflineVulnDBPath string
}

// New returns a detector.
func New() detector.Detector {
	return &Detector{}
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (d Detector) Requirements() *plugin.Capabilities {
	net := plugin.NetworkOnline
	if d.OfflineVulnDBPath == "" {
		net = plugin.NetworkAny
	}
	return &plugin.Capabilities{Network: net, DirectFS: true}
}

// RequiredExtractors returns the go binary extractor.
func (Detector) RequiredExtractors() []string {
	return []string{gobinary.Name}
}

// DetectedFinding returns generic vulnerability information about what is detected.
// TODO: b/428851334 - For now, we do not return any advisories. But we want to be able to propagate
// detection capabilities here.
func (d Detector) DetectedFinding() inventory.Finding {
	return inventory.Finding{}
}

// Scan takes the go binaries gathered in the extraction phase and runs govulncheck on them.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	result := inventory.Finding{}
	scanned := make(map[string]bool)
	var allErrs error
	for _, p := range px.GetAllOfType(purl.TypeGolang) {
		// We only look at Go binaries (no source code).
		if !slices.Contains(p.Plugins, gobinary.Name) {
			continue
		}
		for _, l := range p.Locations {
			if scanned[l] {
				continue
			}
			scanned[l] = true
			if ctx.Err() != nil {
				return result, appendError(allErrs, ctx.Err())
			}
			out, err := d.runGovulncheck(ctx, l, scanRoot.Path)
			if err != nil {
				allErrs = appendError(allErrs, fmt.Errorf("d.runGovulncheck(%s): %w", l, err))
				continue
			}
			r, err := parseVulnsFromOutput(out)
			if err != nil {
				allErrs = appendError(allErrs, fmt.Errorf("d.parseVulnsFromOutput(%v, %s): %w", out, l, err))
				continue
			}
			result.PackageVulns = append(result.PackageVulns, r...)
		}
	}
	return result, allErrs
}

func (d Detector) runGovulncheck(ctx context.Context, binaryPath, scanRoot string) (*bytes.Buffer, error) {
	fullPath := path.Join(scanRoot, binaryPath)
	log.Debugf("Running govulncheck on go binary %v", fullPath)
	args := []string{"--mode=binary", "--json"}
	if d.OfflineVulnDBPath != "" {
		args = append(args, "-db=file://"+d.OfflineVulnDBPath)
	}
	args = append(args, fullPath)
	cmd := scan.Command(ctx, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	log.Debugf("govulncheck complete")
	return &out, nil
}

func parseVulnsFromOutput(out *bytes.Buffer) ([]*inventory.PackageVuln, error) {
	result := []*inventory.PackageVuln{}
	allOSVs := make(map[string]*osvschema.Vulnerability)
	detectedOSVs := make(map[string]struct{}) // osvs detected at the symbol level
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for dec.More() {
		msg := govulncheckMessage{}
		if err := dec.Decode(&msg); err != nil {
			return nil, err
		}
		if msg.OSV != nil {
			allOSVs[msg.OSV.ID] = msg.OSV
		}
		if msg.Finding != nil {
			trace := msg.Finding.Trace
			if len(trace) != 0 && trace[0].Function != "" {
				// symbol findings
				detectedOSVs[msg.Finding.OSV] = struct{}{}
			}
		}
	}

	// create scalibr findings for detected govulncheck findings
	for osvID := range detectedOSVs {
		osv := allOSVs[osvID]
		result = append(result, &inventory.PackageVuln{Vulnerability: *osv})
	}
	return result, nil
}

func appendError(err1, err2 error) error {
	if err1 == nil {
		return err2
	}
	return fmt.Errorf("%w\n%w", err1, err2)
}
