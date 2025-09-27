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

// Package dpkg implements an annotator for language packages that have already been found in
// DPKG OS packages.
package dpkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the Annotator.
	Name            = "vex/os-duplicate/dpkg"
	dpkgInfoDirPath = "var/lib/dpkg/info"
)

// Annotator adds annotations to language packages that have already been found in DPKG OS packages.
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

// Annotate adds annotations to language packages that have already been found in DPKG OS packages.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	locationToPKGs := osduplicate.BuildLocationToPKGsMap(results)

	dirs, err := diriterate.ReadDir(input.ScanRoot.FS, dpkgInfoDirPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Nothing to annotate if we're not running on a DPKG based distro.
			return nil
		}
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
			if err := processListFile(path.Join(dpkgInfoDirPath, f.Name()), input.ScanRoot.FS, locationToPKGs); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
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
					// TODO(b/425890695): This exclusion doesn't quite match the use case here: The component
					// is present but already tracked by another Extractor (os/dpkg). We should consider
					// introducing a new type to better describe these cases.
					Justification:   vex.ComponentNotPresent,
					MatchesAllVulns: true,
				})
			}
		}
	}
	return nil
}
