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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/extractor/filesystem"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
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

func getListFile(input *annotator.ScanInput, pkgName string, pkgArchitecture string) (fs.File, error) {
	options := []string{
		pkgName,
		pkgName + ":" + pkgArchitecture,
	}

	for _, opt := range options {
		listPath := filepath.Join(dpkgInfoDirPath, opt+".list")

		f, err := input.ScanRoot.FS.Open(listPath)
		if err != nil {
			continue
		}
		return f, nil
	}

	return nil, fmt.Errorf("no list file detected for %q", pkgName)
}

// Annotate adds annotations for DPKG packages that don't contain any executables.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	errs := []error{}

	for _, pkg := range results.Packages {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s halted at %q because of context error: %w", a.Name(), input.ScanRoot.Path, err)
		}

		if len(pkg.Locations) == 0 {
			continue
		}

		metadata, ok := pkg.Metadata.(dpkgmetadata.Metadata)
		if !ok {
			continue
		}

		listF, err := getListFile(input, pkg.Name, metadata.Architecture)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// check if the .list files contains at least one executable file
		if listContainsExecutable(listF) {
			continue
		}
		// if the list file does not contain any executable annotate the pkg
		pkg.ExploitabilitySignals = append(pkg.ExploitabilitySignals, &vex.PackageExploitabilitySignal{
			Plugin:          Name,
			Justification:   vex.ComponentNotPresent,
			MatchesAllVulns: true,
		})
	}
	return errors.Join(errs...)
}

// listContainsExecutable open a .list file and check if at least one of the listed file IsInterestingExecutable
func listContainsExecutable(reader io.ReadCloser) bool {
	defer reader.Close()

	s := bufio.NewScanner(reader)
	for s.Scan() {
		mode, err := os.Stat(s.Text())
		if err != nil {
			// TODO: do something here, simply skipping a file could result into a FN
			continue
		}
		api := simplefileapi.New(s.Text(), mode)
		if filesystem.IsInterestingExecutable(api) {
			return true
		}
	}
	return false
}
