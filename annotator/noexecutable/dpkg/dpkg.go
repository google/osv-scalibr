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

// Package dpkg implements an annotator for packages that don't contain any executables.
package dpkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the Annotator.
	Name            = "vex/no-executable/dpkg"
	dpkgInfoDirPath = "var/lib/dpkg/info"
)

// Annotator adds annotations for packages that don't contain any executables.
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

// Annotate adds annotations for packages that don't contain any executables.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	locationToPKGs := osduplicate.BuildLocationToPKGsMap(results)

	dirs, err := diriterate.ReadDir(input.ScanRoot.FS, dpkgInfoDirPath)
	if err != nil {
		return err
	}
	defer dirs.Close()

	errs := []error{}
	for {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("%s halted at %q because of context error: %w", a.Name(), input.ScanRoot.Path, err))
			break
		}

		f, err := dirs.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				errs = append(errs, err)
			}
			break
		}

		if !f.IsDir() && path.Ext(f.Name()) == ".list" {
			listFile := path.Join(dpkgInfoDirPath, f.Name())
			ok, err := containsExecutable(listFile, input.ScanRoot.FS)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if ok {
				continue
			}
			if err := processListFile(listFile, input.ScanRoot.FS, locationToPKGs); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func containsExecutable(path string, fs scalibrfs.FS) (bool, error) {
	reader, err := fs.Open(path)
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

func processListFile(path string, fs scalibrfs.FS, locationToPKGs map[string][]*extractor.Package) error {
	reader, err := fs.Open(path)
	if err != nil {
		return err
	}
	defer reader.Close()

	s := bufio.NewScanner(reader)
	for s.Scan() {
		// Remove leading '/' since SCALIBR fs paths don't include that.
		filePath := strings.TrimPrefix(s.Text(), "/")
		if pkgs, ok := locationToPKGs[filePath]; ok {
			for _, pkg := range pkgs {
				pkg.ExploitabilitySignals = append(pkg.ExploitabilitySignals, &vex.PackageExploitabilitySignal{
					Plugin: Name,
					// TODO: find a better Justification
					Justification:   vex.VulnerableCodeCannotBeControlledByAdversary,
					MatchesAllVulns: true,
				})
			}
		}
	}
	return nil
}
