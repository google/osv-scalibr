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

package python

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"deps.dev/util/pypi"
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/log"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

type requirementsReadWriter struct{}

// GetRequirementsReadWriter returns a ReadWriter for requirements.txt manifest files.
func GetRequirementsReadWriter() (manifest.ReadWriter, error) {
	return requirementsReadWriter{}, nil
}

// System returns the ecosystem of this ReadWriter.
func (r requirementsReadWriter) System() resolve.System {
	return resolve.PyPI
}

// SupportedStrategies returns the remediation strategies supported for this manifest.
func (r requirementsReadWriter) SupportedStrategies() []strategy.Strategy {
	return []strategy.Strategy{strategy.StrategyRelax}
}

// Read parses the manifest from the given file.
func (r requirementsReadWriter) Read(path string, fsys scalibrfs.FS) (manifest.Manifest, error) {
	path = filepath.ToSlash(path)
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	extractor, err := requirements.New(&cpb.PluginConfig{})
	if err != nil {
		return nil, err
	}

	inv, err := extractor.Extract(context.Background(), &filesystem.ScanInput{
		FS:     fsys,
		Path:   path,
		Root:   filepath.Dir(path),
		Reader: f,
	})
	if err != nil {
		return nil, err
	}

	var reqs []resolve.RequirementVersion
	for _, pkg := range inv.Packages {
		m := pkg.Metadata.(*requirements.Metadata)
		if len(m.HashCheckingModeValues) > 0 {
			return nil, errors.New("requirements file in hash checking mode not supported as manifest")
		}
		d, err := pypi.ParseDependency(m.Requirement)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   pkg.Name,
				},
				Version:     d.Constraint,
				VersionType: resolve.Requirement,
			},
		})
	}

	return &pythonManifest{
		filePath: path,
		root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "rootproject",
				},
				VersionType: resolve.Concrete,
				Version:     "1.0.0",
			},
		},
		requirements: reqs,
		groups:       make(map[manifest.RequirementKey][]string),
	}, nil
}

// Write writes the manifest after applying the patches to outputPath.
func (r requirementsReadWriter) Write(original manifest.Manifest, fsys scalibrfs.FS, patches []result.Patch, outputPath string) error {
	return write(fsys, original.FilePath(), outputPath, patches, updateRequirements)
}

// updateRequirements takes an io.Reader representing the requirements.txt file
// and a map of package names to their new version constraints, returns the
// file with the updated requirements as a string.
func updateRequirements(reader io.Reader, requirements []TokenizedRequirements) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("error reading requirements: %w", err)
	}

	var sb strings.Builder
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			sb.WriteString(line)
			continue
		}

		reqLine := line
		// We should trim the comments so they are not part of the requirement.
		if i := strings.Index(reqLine, "#"); i != -1 {
			reqLine = reqLine[:i]
		}
		if strings.TrimSpace(reqLine) == "" {
			sb.WriteString(line)
			continue
		}

		d, err := pypi.ParseDependency(reqLine)
		if err != nil {
			log.Warnf("failed to parse Python dependency %s: %v", line, err)
			sb.WriteString(line)
			continue
		}

		newReq, ok := findTokenizedRequirement(requirements, d.Name, tokenizeRequirement(d.Constraint))
		if !ok {
			// We don't need to update the requirement of this dependency.
			sb.WriteString(line)
			continue
		}
		sb.WriteString(replaceRequirement(line, newReq))
	}

	return sb.String(), nil
}
