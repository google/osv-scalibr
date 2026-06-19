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

// Package requirementsin extracts requirements.in files.
package requirementsin

import (
	"bufio"
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/requirementsin"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

var (
	// Regex matching comments in requirements files.
	reComment = regexp.MustCompile(`(^|\s+)#.*$`)
	// We currently don't handle the following constraints.
	reUnsupportedConstraints = regexp.MustCompile(`\*|<[^=]|,|!=`)
	reWhitespace             = regexp.MustCompile(`[ \t\r]`)
	reValidPkg               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	reExtras                 = regexp.MustCompile(`\[[^\[\]]*\]`)
)

// Extractor extracts python packages from requirements.in files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a requirements.in extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a requirements.in file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "requirements.in" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > noLimitMaxFileSizeBytes && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from requirements.in files.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := extractFromReader(input.Reader, input.Path)

	if e.Stats != nil {
		e.exportStats(input, err)
	}

	return inventory.Inventory{Packages: pkgs}, err
}

func extractFromReader(reader io.Reader, path string) ([]*extractor.Package, error) {
	var pkgs []*extractor.Package
	s := bufio.NewScanner(reader)
	lineNum := 0
	for s.Scan() {
		lineNum++
		l := s.Text()
		l = removeComments(l)
		l = strings.TrimSpace(l)
		l = removeWhiteSpaces(l)
		l = ignorePythonSpecifier(l)
		l = removeExtras(l)

		if len(l) == 0 {
			continue
		}

		if strings.HasPrefix(l, "-") {
			// Global options are not supported in requirements.in input files.
			continue
		}

		name, version, comp := getLowestVersion(l)
		if name == "" {
			continue
		}
		if version == "" && comp != "" {
			continue
		}
		if !isValidPackage(name) {
			continue
		}

		pkgs = append(pkgs, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypePyPi,
			Location: extractor.LocationFromPathAndLine(filepath.ToSlash(path), lineNum),
			Metadata: &requirements.Metadata{
				HashCheckingModeValues: []string{},
				VersionComparator:      comp,
				Requirement:            l,
			},
		})
	}

	return pkgs, s.Err()
}

func (e Extractor) exportStats(input *filesystem.ScanInput, err error) {
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

func nameFromRequirement(s string) string {
	for _, sep := range []string{"===", "==", ">=", "<=", "~=", "!=", "<"} {
		s, _, _ = strings.Cut(s, sep)
	}
	return s
}

func getLowestVersion(s string) (name, version, comparator string) {
	if reUnsupportedConstraints.FindString(s) != "" {
		return nameFromRequirement(s), "", ""
	}

	t := []string{}
	separators := []string{"===", "==", ">=", "<=", "~="}
	comp := ""
	for _, sep := range separators {
		if strings.Contains(s, sep) {
			t = strings.SplitN(s, sep, 2)
			comp = sep
			break
		}
	}

	if len(t) == 0 {
		return s, "", ""
	}
	if len(t) != 2 {
		return "", "", ""
	}

	return t[0], t[1], comp
}

func removeComments(s string) string {
	return reComment.ReplaceAllString(s, "")
}

func removeWhiteSpaces(s string) string {
	return reWhitespace.ReplaceAllString(s, "")
}

func ignorePythonSpecifier(s string) string {
	return strings.SplitN(s, ";", 2)[0]
}

func isValidPackage(s string) bool {
	return reValidPkg.MatchString(s)
}

func removeExtras(s string) string {
	return reExtras.ReplaceAllString(s, "")
}
