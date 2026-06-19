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

// Package constraints extracts constraints files.
package constraints

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
	Name = "python/constraints"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

var (
	// Regex matching comments in constraints files.
	reComment = regexp.MustCompile(`(^|\s+)#.*$`)
	// Regex matching extras in package names, e.g. requests[security].
	reExtras = regexp.MustCompile(`\[[^\[\]]*\]`)
	// Regex matching valid Python distribution names.
	reValidPkg = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	// Regex matching version operators, ordered longest first.
	reVersionOperators = regexp.MustCompile(`===|==|>=|<=|~=|!=|>|<`)
)

// Extractor extracts python packages from constraints.txt files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a constraints.txt extractor.
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
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches a constraints.txt file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "constraints.txt" {
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

// Extract extracts packages from constraints.txt files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := extractFromPath(input.Reader, input.Path)

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
	return inventory.Inventory{Packages: pkgs}, err
}

func extractFromPath(reader io.Reader, path string) ([]*extractor.Package, error) {
	var pkgs []*extractor.Package
	s := bufio.NewScanner(reader)
	lineNum := 0
	for s.Scan() {
		lineNum++
		l := s.Text()
		l = removeComments(l)
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		// Ignore Python environment markers.
		l = strings.SplitN(l, ";", 2)[0]
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		// Remove extras from package names.
		l = removeExtras(l)

		name, version, comp := getNameAndVersion(l)
		if name == "" {
			continue
		}
		if version == "" && comp != "" {
			// Version should be non-empty if there is a comparator.
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

func getNameAndVersion(s string) (name, version, comparator string) {
	match := reVersionOperators.FindStringIndex(s)
	if match == nil {
		return strings.TrimSpace(s), "", ""
	}
	comp := s[match[0]:match[1]]
	name = strings.TrimSpace(s[:match[0]])
	version = strings.TrimSpace(s[match[1]:])
	return name, version, comp
}

func removeComments(s string) string {
	return reComment.ReplaceAllString(s, "")
}

func removeExtras(s string) string {
	return reExtras.ReplaceAllString(s, "")
}

func isValidPackage(s string) bool {
	return reValidPkg.MatchString(s)
}
