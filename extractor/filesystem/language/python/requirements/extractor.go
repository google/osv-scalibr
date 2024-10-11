// Copyright 2024 Google LLC
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

// Package requirements extracts requirements files.
package requirements

import (
	"bufio"
	"context"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/internal/pypipurl"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

var (
	// Regex matching comments in requirements files.
	// https://github.com/pypa/pip/blob/72a32e/src/pip/_internal/req/req_file.py#L492
	reComment = regexp.MustCompile(`(^|\s+)#.*$`)
	// We currently don't handle the following constraints.
	// * Version wildcards (*)
	// * Less than (<)
	// * Multiple constraints (,)
	reUnsupportedConstraints        = regexp.MustCompile(`\*|<|,`)
	reWhitespace                    = regexp.MustCompile(`[ \t\r]`)
	reValidPkg                      = regexp.MustCompile(`^\w(\w|-)+$`)
	reEnvVar                        = regexp.MustCompile(`(?P<var>\$\{(?P<name>[A-Z0-9_]+)\})`)
	reExtras                        = regexp.MustCompile(`\[[^\[\]]*\]`)
	reTextAfterFirstOptionInclusive = regexp.MustCompile(`(?:--hash|--global-option|--config-settings|-C).*`)
	reHashOption                    = regexp.MustCompile(`--hash=(.+?)(?:$|\s)`)
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: 0,
	}
}

// Extractor extracts python packages from requirements.txt files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a requirements.txt extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return "python/requirements" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches python Metadata file
// patterns.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	if filepath.Ext(path) != ".txt" || !strings.Contains(filepath.Base(path), "requirements") {
		return false
	}

	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from requirements files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	// File paths with inventories already found in this extraction.
	// We store these to remove duplicates in diamond dependency cases and prevent
	// infinite loops in misconfigured lockfiles with cyclical deps.
	var found = map[string]struct{}{}
	inventory, err := e.extractFromPath(ctx, input.Reader, input.Path, input.FS, found)
	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory, err
}

func (e Extractor) extractFromPath(ctx context.Context, reader io.Reader, path string, fs scalibrfs.FS, found map[string]struct{}) ([]*extractor.Inventory, error) {
	// Prevent infinite loop on dep cycles.
	if _, ok := found[path]; ok {
		return nil, nil
	}
	found[path] = struct{}{}

	inventory := []*extractor.Inventory{}
	s := bufio.NewScanner(reader)
	carry := ""
	for s.Scan() {
		l := carry + s.Text()
		carry = ""
		l = removeComments(l)
		if strings.HasSuffix(l, `\`) {
			carry = l[:len(l)-1]
			continue
		}

		if hasEnvVariable(l) {
			// Ignore env variables
			// https://github.com/pypa/pip/blob/72a32e/src/pip/_internal/req/req_file.py#L503
			// TODO(b/286213823): Implement metric
			continue
		}

		// Per-requirement options may be present. We extract the --hash options, and discard the others.
		l, hashOptions := splitPerRequirementOptions(l)

		l = removeWhiteSpaces(l)
		l = ignorePythonSpecifier(l)
		l = removeExtras(l)

		if len(l) == 0 {
			// Ignore empty lines
			continue
		}

		// Parse referenced requirements.txt files as well.
		if strings.HasPrefix(l, "-r") {
			p := strings.TrimPrefix(l, "-r")
			// Path is relative to the current requirement file's dir.
			p = filepath.Join(filepath.Dir(path), p)
			r, err := fs.Open(filepath.ToSlash(p))
			if err != nil {
				log.Warnf("Open(%s): %w", p, err)
				continue
			}
			invs, err := e.extractFromPath(ctx, r, p, fs, found)
			if err != nil {
				log.Warnf("extractFromPath(%s): %w", p, err)
				continue
			}
			for _, i := range invs {
				// Note the path through which we refer to this requirements.txt file.
				i.Locations[0] = path + ":" + filepath.ToSlash(i.Locations[0])
				// Also note original file as an OSV dependency group.
				inventory = append(inventory, i)
			}
			continue
		}

		if strings.HasPrefix("-", l) {
			// Global options other than -r are not implemented.
			// https://pip.pypa.io/en/stable/reference/requirements-file-format/#global-options
			// TODO(b/286213823): Implement metric
			continue
		}

		name, version, comp := getLowestVersion(l)
		if name == "" || version == "" {
			// Either empty
			continue
		}
		if !isValidPackage(name) {
			// TODO(b/286213823): Implement Metric
			continue
		}

		inventory = append(inventory, &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{path},
			Metadata: &Metadata{
				HashCheckingModeValues: hashOptions,
				VersionComparator:      comp,
			},
		})
	}

	return inventory, s.Err()
}

func removeComments(s string) string {
	return reComment.ReplaceAllString(s, "")
}

func getLowestVersion(s string) (name, version, comparator string) {
	// TODO(b/286213823): Implement metric
	if reUnsupportedConstraints.FindString(s) != "" {
		return "", "", ""
	}

	t := []string{}
	separators := []string{"===", "==", ">=", "~="}
	comp := ""
	for _, sep := range separators {
		if strings.Contains(s, sep) {
			t = strings.SplitN(s, sep, 2)
			comp = sep
			break
		}
	}

	if len(t) != 2 {
		return "", "", ""
	}

	// For all other separators the lowest version is the one we found.
	return t[0], t[1], comp
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

func hasEnvVariable(s string) bool {
	return reEnvVar.FindString(s) != ""
}

// splitPerRequirementOptions removes from the input all text after the first per requirement option
// and returns the remaining input along with the values of the --hash options. See the documentation
// in https://pip.pypa.io/en/stable/reference/requirements-file-format/#per-requirement-options.
func splitPerRequirementOptions(s string) (string, []string) {
	hashes := []string{}
	for _, hashOptionMatch := range reHashOption.FindAllStringSubmatch(s, -1) {
		hashes = append(hashes, hashOptionMatch[1])
	}
	return reTextAfterFirstOptionInclusive.ReplaceAllString(s, ""), hashes
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return pypipurl.MakePackageURL(i), nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) (string, error) { return "PyPI", nil }
