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
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
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
	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by `FileRequired`.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Regex pattern strings for SBT dependency extraction.
const (
	// depWithInlineVersionPattern matches SBT dependency declarations with an inline string version:
	//   libraryDependencies += "groupId" %{1,3} "artifactId" % "version"
	// The version must be numeric (digits and dots only, e.g. "1.0.0").
	// It also handles an optional 4th part (configuration) like `% Test` which is ignored.
	// Capture groups: 1=groupId, 2=artifactId, 3=version
	depWithInlineVersionPattern = `libraryDependencies\s*\+=\s*"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*"([0-9]+(?:\.[0-9]+)*)"`

	// depWithVarVersionPattern matches SBT dependency declarations where the version is a variable reference:
	//   libraryDependencies += "groupId" %{1,3} "artifactId" % someVariable
	// Capture groups: 1=groupId, 2=artifactId, 3=variableName
	depWithVarVersionPattern = `libraryDependencies\s*\+=\s*"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*([a-zA-Z_][a-zA-Z0-9_]*)`

	// seqBlockPattern matches the body of a libraryDependencies ++= Seq(...) block.
	// Capture group: 1=contents inside Seq(...)
	seqBlockPattern = `libraryDependencies\s*\+\+=\s*Seq\s*\(((?:[^)]*\n?)*?)\)`

	// seqDepInlineVersionPattern matches a single dependency entry inside a Seq block with an inline version:
	//   "groupId" %{1,3} "artifactId" % "version"
	// Capture groups: 1=groupId, 2=artifactId, 3=version
	seqDepInlineVersionPattern = `"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*"([0-9]+(?:\.[0-9]+)*)"`

	// seqDepVarVersionPattern matches a single dependency entry inside a Seq block with a variable version:
	//   "groupId" %{1,3} "artifactId" % someVariable
	// Capture groups: 1=groupId, 2=artifactId, 3=variableName
	seqDepVarVersionPattern = `"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*([a-zA-Z_][a-zA-Z0-9_]*)`
)

// resolveVariable looks up a variable's string value in the full file content
// by searching for a matching val definition. The value must be a numeric version
// (digits and dots only).
func resolveVariable(varName, content string) (string, bool) {
	// Build a specific regex for this variable name to find its val definition.
	re, err := regexp.Compile(`val\s+` + regexp.QuoteMeta(varName) + `\s*=\s*"([0-9]+(?:\.[0-9]+)*)"`)
	if err != nil {
		return "", false
	}
	m := re.FindStringSubmatch(content)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Extractor extracts Maven packages from SBT build files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a new instance of the extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.SBT {
		return c.GetSbt()
	})
	if specific != nil {
		if specific.GetMaxFileSizeBytes() > 0 {
			maxFileSizeBytes = specific.GetMaxFileSizeBytes()
		}
	}
	return &Extractor{
		maxFileSizeBytes: maxFileSizeBytes,
	}, nil
}

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

	depWithInlineVersionReg, err := regexp.Compile(depWithInlineVersionPattern)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("sbt: failed to compile depWithInlineVersion regex: %w", err)
	}
	depWithVarVersionReg, err := regexp.Compile(depWithVarVersionPattern)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("sbt: failed to compile depWithVarVersion regex: %w", err)
	}
	seqBlockReg, err := regexp.Compile(seqBlockPattern)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("sbt: failed to compile seqBlock regex: %w", err)
	}
	seqDepInlineVersionReg, err := regexp.Compile(seqDepInlineVersionPattern)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("sbt: failed to compile seqDepInlineVersion regex: %w", err)
	}
	seqDepVarVersionReg, err := regexp.Compile(seqDepVarVersionPattern)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("sbt: failed to compile seqDepVarVersion regex: %w", err)
	}

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

	// Extract dependencies from libraryDependencies ++= Seq(...) blocks.
	for _, block := range seqBlockReg.FindAllStringSubmatch(text, -1) {
		body := block[1]

		// Extract inline-versioned dependencies from the Seq body.
		for _, m := range seqDepInlineVersionReg.FindAllStringSubmatch(body, -1) {
			packages = append(packages, makePackage(m[1], m[2], m[3], input.Path))
		}

		// Extract variable-versioned dependencies from the Seq body.
		for _, m := range seqDepVarVersionReg.FindAllStringSubmatch(body, -1) {
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
