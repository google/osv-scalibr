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

package gomod

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/purl"
)

// extractFromSum extracts dependencies from the go.sum file.
//
// Below 1.17 go.mod does not contain indirect dependencies
// but they might be in go.sum, thus we look into it as well.
//
// Note: This function may produce false positives, as the go.sum file might be outdated.
func extractFromSum(input *filesystem.ScanInput) (map[pkgKey]*extractor.Package, error) {
	goSumPath := strings.TrimSuffix(input.Path, ".mod") + ".sum"
	f, err := input.FS.Open(goSumPath)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(f)
	packages := map[pkgKey]*extractor.Package{}

	for lineNumber := 0; scanner.Scan(); lineNumber++ {
		line := scanner.Text()

		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			return nil, fmt.Errorf("error reading line: %d", lineNumber)
		}

		name := parts[0]
		version := strings.TrimPrefix(parts[1], "v")

		// skip a line if the version contains "/go.mod" because lines
		// containing "/go.mod" are duplicates used to verify the hash of the go.mod file
		if strings.Contains(version, "/go.mod") {
			continue
		}

		packages[pkgKey{name: name, version: version}] = &extractor.Package{
			Name:      name,
			Version:   version,
			PURLType:  purl.TypeGolang,
			Locations: []string{goSumPath},
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}
