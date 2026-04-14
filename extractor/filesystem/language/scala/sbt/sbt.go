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
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "scala/sbt"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Extractor extracts Maven packages from Scala SBT build files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64

	// Pre-compiled regexes, initialized once in New().
	depInlineRe    *regexp.Regexp
	depVarRe       *regexp.Regexp
	seqBlockRe     *regexp.Regexp
	seqDepInlineRe *regexp.Regexp
	seqDepVarRe    *regexp.Regexp
}

// New returns a new instance of the extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	return &Extractor{
		maxFileSizeBytes: maxFileSizeBytes,
		depInlineRe:      regexp.MustCompile(`libraryDependencies\s*\+=\s*"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*"([0-9]+(?:\.[0-9]+)*)"`),
		depVarRe:         regexp.MustCompile(`libraryDependencies\s*\+=\s*"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*([a-zA-Z_][a-zA-Z0-9_]*)`),
		seqBlockRe:       regexp.MustCompile(`(?s)libraryDependencies\s*\+\+=\s*Seq\s*\((.*?)\)`),
		seqDepInlineRe:   regexp.MustCompile(`"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*"([0-9]+(?:\.[0-9]+)*)"`),
		seqDepVarRe:      regexp.MustCompile(`"([^"]+)"\s*%%?%?\s*"([^"]+)"\s*%\s*([a-zA-Z_][a-zA-Z0-9_]*)`),
	}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is an SBT build file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Ext(path) != ".sbt" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil || (e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes) {
		e.reportFileRequired(path, stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:   path,
		Result: result,
	})
}

// Extract extracts packages from SBT build files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read sbt file %s: %w", input.Path, err)
	}
	text := string(content)

	var packages []*extractor.Package

	// Extract single dependencies: libraryDependencies += "g" %% "a" % "v"
	for _, m := range e.depInlineRe.FindAllStringSubmatch(text, -1) {
		packages = append(packages, makePackage(m[1], m[2], m[3], input.Path))
	}

	// Extract single dependencies with variable version: libraryDependencies += "g" %% "a" % ver
	for _, m := range e.depVarRe.FindAllStringSubmatch(text, -1) {
		version, ok := resolveVariable(m[3], text)
		if !ok {
			log.Warnf("sbt: unresolved version variable %q for %s:%s in %s", m[3], m[1], m[2], input.Path)
			continue
		}
		packages = append(packages, makePackage(m[1], m[2], version, input.Path))
	}

	// Extract Seq block dependencies: libraryDependencies ++= Seq(...)
	for _, block := range e.seqBlockRe.FindAllStringSubmatch(text, -1) {
		body := block[1]
		for _, m := range e.seqDepInlineRe.FindAllStringSubmatch(body, -1) {
			packages = append(packages, makePackage(m[1], m[2], m[3], input.Path))
		}
		for _, m := range e.seqDepVarRe.FindAllStringSubmatch(body, -1) {
			version, ok := resolveVariable(m[3], text)
			if !ok {
				log.Warnf("sbt: unresolved version variable %q for %s:%s in %s", m[3], m[1], m[2], input.Path)
				continue
			}
			packages = append(packages, makePackage(m[1], m[2], version, input.Path))
		}
	}

	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

// resolveVariable looks up a val definition for the given variable name.
func resolveVariable(varName, content string) (string, bool) {
	re, err := regexp.Compile(`(?:val|lazy\s+val)\s+` + regexp.QuoteMeta(varName) + `\s*=\s*"([0-9]+(?:\.[0-9]+)*)"`)
	if err != nil {
		return "", false
	}
	m := re.FindStringSubmatch(content)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func makePackage(groupID, artifactID, version, path string) *extractor.Package {
	return &extractor.Package{
		Name:     groupID + ":" + artifactID,
		Version:  version,
		PURLType: purl.TypeMaven,
		Location: extractor.LocationFromPath(path),
		Metadata: &javalockfile.Metadata{
			ArtifactID:   artifactID,
			GroupID:      groupID,
			DepGroupVals: []string{},
		},
	}
}

var _ filesystem.Extractor = Extractor{}
