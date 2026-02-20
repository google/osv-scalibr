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

// Package sbt extracts dependencies from Scala SBT build files (.sbt).
package sbt

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "scala/sbt"
)

// Compiled regexes for SBT dependency extraction.
var (
	// depWithInlineVersionReg matches SBT dependency declarations with an inline string version:
	//   libraryDependencies += "groupId" %{1,3} "artifactId" % "version"
	// The version must be numeric (digits and dots only, e.g. "1.0.0").
	// It also handles an optional 4th part (configuration) like `% Test` which is ignored.
	// Capture groups: 1=groupId, 2=artifactId, 3=version
	depWithInlineVersionReg = regexp.MustCompile(
		`libraryDependencies\s*\+=\s*"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*"([0-9]+(?:\.[0-9]+)*)"`,
	)

	// depWithVarVersionReg matches SBT dependency declarations where the version is a variable reference:
	//   libraryDependencies += "groupId" %{1,3} "artifactId" % someVariable
	// Capture groups: 1=groupId, 2=artifactId, 3=variableName
	depWithVarVersionReg = regexp.MustCompile(
		`libraryDependencies\s*\+=\s*"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*([a-zA-Z_][a-zA-Z0-9_]*)`,
	)
)

// resolveVariable looks up a variable's string value in the full file content
// by searching for a matching val definition. The value must be a numeric version
// (digits and dots only).
func resolveVariable(varName, content string) (string, bool) {
	// Build a specific regex for this variable name to find its val definition.
	re := regexp.MustCompile(`val\s+` + regexp.QuoteMeta(varName) + `\s*=\s*"([0-9]+(?:\.[0-9]+)*)"`)
	m := re.FindStringSubmatch(content)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Extractor extracts Maven packages from SBT build files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is an SBT build file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Ext(api.Path()) == ".sbt"
}

// Extract extracts packages from SBT build files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read sbt file %s: %w", input.Path, err)
	}
	text := string(content)

	var packages []*extractor.Package

	// Extract dependencies with inline quoted versions.
	for _, m := range depWithInlineVersionReg.FindAllStringSubmatch(text, -1) {
		packages = append(packages, makePackage(m[1], m[2], m[3], input.Path))
	}

	// Extract dependencies with variable version references.
	for _, m := range depWithVarVersionReg.FindAllStringSubmatch(text, -1) {
		groupID := m[1]
		artifactID := m[2]
		varName := m[3]

		version, ok := resolveVariable(varName, text)
		if !ok {
			log.Warnf("sbt: unresolved version variable %q for %s:%s in %s", varName, groupID, artifactID, input.Path)
			continue
		}
		packages = append(packages, makePackage(groupID, artifactID, version, input.Path))
	}

	return inventory.Inventory{Packages: packages}, nil
}

func makePackage(groupID, artifactID, version, path string) *extractor.Package {
	return &extractor.Package{
		Name:      groupID + ":" + artifactID,
		Version:   version,
		PURLType:  purl.TypeMaven,
		Locations: []string{path},
		Metadata: &javalockfile.Metadata{
			ArtifactID:   artifactID,
			GroupID:      groupID,
			DepGroupVals: []string{},
		},
	}
}

var _ filesystem.Extractor = Extractor{}
