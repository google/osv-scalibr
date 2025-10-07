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
	"io/fs"
	"path/filepath"
	"strings"

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

// Annotate adds annotations for DPKG packages that don't contain any executables.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	errs := []error{}

	// early exit if the dpkgInfoDirPath does not exists
	if _, err := input.ScanRoot.FS.Stat(dpkgInfoDirPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Nothing to annotate if we're not running on a DPKG based distro.
			return nil
		}
		return fmt.Errorf("folder %q does not exists", dpkgInfoDirPath)
	}

	for _, pkg := range results.Packages {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s halted at %q because of context error: %w", a.Name(), input.ScanRoot.Path, err)
		}

		metadata, ok := pkg.Metadata.(dpkgmetadata.Metadata)
		if !ok {
			continue
		}

		// check if the pkg files contains at least one executable file
		containsExecutable, err := pkgContainsExecutable(ctx, input, pkg.Name, metadata.Architecture)
		// if the pkg contains an executable or there was an error checking the files, skip the pkg
		// here, false positives are better then false negatives
		if containsExecutable || err != nil {
			errs = append(errs, err)
			continue
		}

		// if the pkg does not contain any executable then add an annotation
		pkg.ExploitabilitySignals = append(pkg.ExploitabilitySignals, &vex.PackageExploitabilitySignal{
			Plugin:          Name,
			Justification:   vex.ComponentNotPresent,
			MatchesAllVulns: true,
		})
	}
	return errors.Join(errs...)
}

// pkgContainsExecutable opens a pkg related .list file and check if at least one of the listed file IsInterestingExecutable
func pkgContainsExecutable(ctx context.Context, input *annotator.ScanInput, pkgName, pkgArchitecture string) (bool, error) {
	listF, err := getListFile(input, pkgName, pkgArchitecture)
	if err != nil {
		return false, err
	}
	defer listF.Close()

	s := bufio.NewScanner(listF)
	errs := []error{}
	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return false, fmt.Errorf("%s halted at %q because of context error: %w", pkgName, input.ScanRoot.Path, err)
		}

		// Remove leading '/' since SCALIBR fs paths don't include that.
		filePath := strings.TrimPrefix(s.Text(), "/")

		info, err := input.ScanRoot.FS.Stat(filePath)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if info.IsDir() {
			continue
		}

		api := simplefileapi.New(filePath, info)
		if filesystem.IsInterestingExecutable(api) {
			return true, errors.Join(errs...)
		}
	}
	return false, errors.Join(errs...)
}

// getListFile given a pkgName and pkgArchitecture returns a DPKG .list file containing all the installed files
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
