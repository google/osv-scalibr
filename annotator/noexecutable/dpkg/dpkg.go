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

// Package dpkg implements an annotator for DPKG packages that don't contain any executables.
package dpkg

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the Annotator.
	Name            = "vex/no-executable/dpkg"
	dpkgInfoDirPath = "var/lib/dpkg/info"
)

// Annotator adds annotations for DPKG packages that don't contain any executables.
type Annotator struct{}

// New returns a new Annotator.
func New() annotator.Annotator { return &Annotator{} }

// Name of the annotator.
func (Annotator) Name() string { return Name }

// Version of the annotator.
func (Annotator) Version() int { return 0 }

// Requirements of the annotator.
func (Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSLinux}
}

func fileRequired(path string) bool {
	normalized := filepath.ToSlash(path)

	// Normal status file matching DPKG or OPKG format
	if normalized == "var/lib/dpkg/status" || normalized == "usr/lib/opkg/status" {
		return true
	}

	// Should only match status files in status.d directory.
	return strings.HasPrefix(normalized, "var/lib/dpkg/status.d/") && !strings.HasSuffix(normalized, ".md5sums")
}

// Annotate adds annotations for DPKG packages that don't contain any executables.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	locationToPKGs := osduplicate.BuildLocationToPKGsMap(results)

	errors := []error{}
	for location, pkgs := range locationToPKGs {
		// check if the pkgs are DPKG
		if !fileRequired(location) {
			continue
		}

		// for each pkg access the .list file
		for _, pkg := range pkgs {
			listFile := filepath.Join(dpkgInfoDirPath, pkg.Name)

			// check if the .list files contains at least one executable file
			containsExecutable, err := listContainsExecutable(listFile, input)
			// if an error happens do nothing, false positives are better than false negatives
			if err != nil {
				errors = append(errors, err)
				continue
			}
			if containsExecutable {
				continue
			}
			// if the list file does not contain any binary annotate the pkg
			pkg.ExploitabilitySignals = append(pkg.ExploitabilitySignals, &vex.PackageExploitabilitySignal{
				Plugin:          Name,
				Justification:   vex.ComponentNotPresent,
				MatchesAllVulns: true,
			})
		}
	}
	return nil
}

// listContainsExecutable open a .list file and check if at least one of the listed file IsInterestingExecutable
func listContainsExecutable(path string, input *annotator.ScanInput) (bool, error) {
	reader, err := input.ScanRoot.FS.Open(path)
	if err != nil {
		return false, err
	}
	defer reader.Close()

	s := bufio.NewScanner(reader)
	for s.Scan() {
		mode, err := os.Stat(s.Text())
		if err != nil {
			// TODO: do something
			continue
		}
		api := simplefileapi.New(s.Text(), mode)
		if filesystem.IsInterestingExecutable(api) {
			return true, nil
		}
	}
	return false, nil
}
