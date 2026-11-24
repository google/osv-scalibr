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

//go:build linux

package rpm

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	rpmdb "github.com/erikvarga/go-rpmdb/pkg"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"

	// SQLite driver needed for parsing rpmdb.sqlite files.
	_ "modernc.org/sqlite"
)

var (
	// Directories and files where RPM descriptor packages can be found.
	rpmDirectories = []string{
		"usr/lib/sysimage/rpm/",
		"var/lib/rpm/",
		"usr/share/rpm/",
	}
	rpmFilenames = []string{
		// Berkley DB (old format)
		"Packages",
		// NDB (very rare alternative to sqlite)
		"Packages.db",
		// SQLite3 (new format)
		"rpmdb.sqlite",
	}
)

// Annotate adds annotations to language packages that have already been found in RPM OS packages.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	locationToPKGs := osduplicate.BuildLocationToPKGsMap(results, input.ScanRoot)

	mainPackages, err := extractMainPackages(ctx, input.ScanRoot)
	if err != nil && !errors.Is(err, ErrMissingCache) && !errors.Is(err, ErrMissingOSInfo) && !errors.Is(err, ErrPackageManagerNotSupported) {
		return fmt.Errorf("error extracting main packages metadata %w", err)
	}

	var errs []error
	for _, dir := range rpmDirectories {
		for _, file := range rpmFilenames {
			// Return if canceled or exceeding deadline.
			if err := ctx.Err(); err != nil {
				errs = append(errs, fmt.Errorf("%s halted at %q because of context error: %w", a.Name(), input.ScanRoot.Path, err))
				break
			}

			dbPath := path.Join(dir, file)
			// Skip files that don't exist or are directories.
			if info, err := fs.Stat(input.ScanRoot.FS, dbPath); err != nil || info.IsDir() {
				continue
			}

			if err := a.annotatePackagesInRPMDB(ctx, input.ScanRoot, dbPath, mainPackages, locationToPKGs); err != nil {
				return err
			}
		}
	}

	return errors.Join(errs...)
}

func (a *Annotator) annotatePackagesInRPMDB(ctx context.Context, root *scalibrfs.ScanRoot, dbPath string, mainPackages *mainOSPackages, locationToPKGs map[string][]*extractor.Package) error {
	var (
		realDBPath string
		cleanup    func() error
		err        error
	)
	if strings.HasSuffix(dbPath, ".sqlite") {
		// erikvarga/go-rpmdb opens SQLite databases without ?mode=ro&immutable=1
		// and rejects file: URIs, so keep an isolated copy for .sqlite DBs.
		realDBPath, err = scalibrfs.GetRealPath(root, dbPath, nil)
		if err != nil {
			return fmt.Errorf("GetRealPath(%q): %w", dbPath, err)
		}
		cleanup = func() error { return os.RemoveAll(filepath.Dir(realDBPath)) }
	} else {
		realDBPath, cleanup, err = scalibrfs.OpenOSPath(root, dbPath, nil)
		if err != nil {
			return fmt.Errorf("OpenOSPath(%q): %w", dbPath, err)
		}
	}
	defer func() {
		if err := cleanup(); err != nil {
			log.Errorf("cleanup(%q): %v", realDBPath, err)
		}
	}()

	db, err := rpmdb.Open(realDBPath)
	if err != nil {
		return fmt.Errorf("error reading db: %w", err)
	}
	defer db.Close()

	if a.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.Timeout)
		defer cancel()
	}

	rpmPkgs, err := db.ListPackagesWithContext(ctx)
	if err != nil {
		return err
	}

	for _, rpmPkg := range rpmPkgs {
		if mainPackages != nil && !mainPackages.Contains(rpmPkg) {
			continue
		}

		for i, base := range rpmPkg.BaseNames {
			if len(rpmPkg.DirIndexes) <= i {
				return fmt.Errorf("malformed RPM directory index: want %d entries, got %d", i+1, len(rpmPkg.DirIndexes))
			}

			dir := rpmPkg.DirNames[rpmPkg.DirIndexes[i]]
			// Remove leading '/' since SCALIBR fs paths don't include that.
			pkgPath := strings.TrimPrefix(path.Join(dir, base), "/")

			for _, extPkg := range locationToPKGs[pkgPath] {
				hasSignal := slices.ContainsFunc(extPkg.ExploitabilitySignals, func(s *vex.PackageExploitabilitySignal) bool {
					return s.Plugin == Name
				})
				if hasSignal {
					continue
				}

				extPkg.ExploitabilitySignals = append(extPkg.ExploitabilitySignals, &vex.PackageExploitabilitySignal{
					Plugin:          Name,
					Justification:   vex.ComponentNotPresent,
					MatchesAllVulns: true,
				})
			}
		}
	}

	return nil
}
