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

// Package apk implements an annotator for language packages that have already been found in
// APK OS packages.
package apk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the Annotator.
	Name           = "vex/os-duplicate/apk"
	apkInstalledDB = "lib/apk/db/installed"
)

// Annotator adds annotations to language packages that have already been found in APK OS packages.
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

// parseSingleApkRecord reads from the scanner a single record,
// returns nil, nil when scanner ends.
func parseSingleApkRecord(scanner *bufio.Scanner) (map[string]string, error) {
	// There is currently 26 keys defined here (Under "Installed Database V2"):
	// https://wiki.alpinelinux.org/wiki/Apk_spec
	group := map[string]string{}

	for scanner.Scan() {
		line := scanner.Text()

		if line != "" {
			key, val, found := strings.Cut(line, ":")

			if !found {
				return nil, fmt.Errorf("invalid line: %q", line)
			}

			group[key] = val
			continue
		}

		// check both that line is empty and we have filled out data in group
		// this avoids double empty lines returning early
		if line == "" && len(group) > 0 {
			// scanner.Err() could only be non nil when Scan() returns false
			// so we can return nil directly here
			return group, nil
		}
	}

	return group, scanner.Err()
}

// Annotate adds annotations to language packages that have already been found in APK OS packages.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	locationToPKGs := osduplicate.BuildLocationToPKGsMap(results)

	f, err := input.ScanRoot.FS.Open(apkInstalledDB)
	if err != nil {
		return err
	}
	defer f.Close()

	errs := []error{}

	scanner := bufio.NewScanner(f)
	for {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("%s halted at %q because of context error: %w", a.Name(), input.ScanRoot.Path, err))
			break
		}

		record, err := parseSingleApkRecord(scanner)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while parsing apk status file %q: %w", input.ScanRoot.Path, err))
			return errors.Join(errs...)
		}

		if len(record) == 0 {
			break
		}

		folder := record["F"]
		filename := record["R"]

		// if the filePath is not retrievable continue to the next package
		if folder == "" || filename == "" {
			continue
		}

		filePath := path.Join(folder, filename)

		if pkgs, ok := locationToPKGs[filePath]; ok {
			for _, pkg := range pkgs {
				pkg.ExploitabilitySignals = append(pkg.ExploitabilitySignals, &vex.PackageExploitabilitySignal{
					Plugin:          Name,
					Justification:   vex.ComponentNotPresent,
					MatchesAllVulns: true,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
