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

// Package gradlelockfile extracts pom.xml files.
package gradlelockfile

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/gradlelockfile"

	gradleLockFileCommentPrefix = "#"
	gradleLockFileEmptyPrefix   = "empty="
)

func isGradleLockFileDepLine(line string) bool {
	ret := strings.HasPrefix(line, gradleLockFileCommentPrefix) ||
		strings.HasPrefix(line, gradleLockFileEmptyPrefix)

	return !ret
}

func parseToGradlePackageDetail(line string) (*extractor.Package, error) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid line in gradle lockfile: %s", line)
	}

	group, artifact, version := parts[0], parts[1], parts[2]
	if !strings.Contains(version, "=") {
		return nil, fmt.Errorf("invalid line in gradle lockfile: %s", line)
	}
	version = strings.SplitN(version, "=", 2)[0]

	return &extractor.Package{
		Name:     fmt.Sprintf("%s:%s", group, artifact),
		Version:  version,
		PURLType: purl.TypeMaven,
		Metadata: &javalockfile.Metadata{
			ArtifactID: artifact,
			GroupID:    group,
		},
	}, nil
}

// Extractor extracts Maven packages from Gradle files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Gradle lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())

	return slices.Contains([]string{"buildscript-gradle.lockfile", "gradle.lockfile"}, base)
}

// Extract extracts packages from Gradle files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages := make([]*extractor.Package, 0)
	scanner := bufio.NewScanner(input.Reader)

	for scanner.Scan() {
		lockLine := strings.TrimSpace(scanner.Text())
		if !isGradleLockFileDepLine(lockLine) {
			continue
		}

		pkg, err := parseToGradlePackageDetail(lockLine)
		if err != nil {
			continue
		}

		pkg.Locations = []string{input.Path}

		packages = append(packages, pkg)
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read: %w", err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
