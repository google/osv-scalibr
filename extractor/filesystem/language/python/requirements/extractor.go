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
func (e Extractor) FileRequired(path string, stat func() (fs.FileInfo, error)) bool {
	if filepath.Ext(path) != ".txt" || !strings.Contains(filepath.Base(path), "requirements") {
		return false
	}

	fileinfo, err := stat()
	if err != nil {
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

type pathQueue []string

// Extract extracts packages from requirements files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	// Additional paths to recursive files found during extraction.
	var extraPaths pathQueue
	var inv []*extractor.Inventory
	newRepos, newPaths, err := extractFromPath(input.Reader, input.Path, input.FS)
	if err != nil {
		return nil, err
	}
	if e.stats != nil {
		e.exportStats(input, err)
	}
	extraPaths = append(extraPaths, newPaths...)
	inv = append(inv, newRepos...)

	// Process all the recursive files that we found.
	extraInv := extractFromExtraPaths(input.Path, extraPaths, input.FS)
	inv = append(inv, extraInv...)

	return inv, nil
}

func extractFromExtraPaths(initPath string, extraPaths pathQueue, fs scalibrfs.FS) []*extractor.Inventory {
	// File paths with inventories already found in this extraction.
	// We store these to remove duplicates in diamond dependency cases and prevent
	// infinite loops in misconfigured lockfiles with cyclical deps.
	var found = map[string]bool{initPath: true}
	var inv []*extractor.Inventory

	for len(extraPaths) > 0 {
		path := extraPaths[0]
		extraPaths = extraPaths[1:]
		if _, exists := found[path]; exists {
			continue
		}
		newInv, newPaths, err := openAndExtractFromFile(path, fs)
		if err != nil {
			log.Warnf("openAndExtractFromFile(%s): %w", path, err)
			continue
		}
		found[path] = true
		extraPaths = append(extraPaths, newPaths...)
		for _, i := range newInv {
			// Note the path through which we refer to this requirements.txt file.
			i.Locations[0] = initPath + ":" + filepath.ToSlash(i.Locations[0])
		}
		inv = append(inv, newInv...)
	}

	return inv
}

func openAndExtractFromFile(path string, fs scalibrfs.FS) ([]*extractor.Inventory, pathQueue, error) {
	reader, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()
	return extractFromPath(reader, path, fs)
}

func extractFromPath(reader io.Reader, path string, fs scalibrfs.FS) ([]*extractor.Inventory, pathQueue, error) {
	var inv []*extractor.Inventory
	var extraPaths pathQueue
	s := bufio.NewScanner(reader)
	for s.Scan() {
		l := readLine(s, &strings.Builder{})
		// Per-requirement options may be present. We extract the --hash options, and discard the others.
		l, hashOptions := splitPerRequirementOptions(l)
		l = removeWhiteSpaces(l)
		l = ignorePythonSpecifier(l)
		l = removeExtras(l)

		if len(l) == 0 {
			continue
		}

		// Extract paths to referenced requirements.txt files for further processing.
		if strings.HasPrefix(l, "-r") {
			p := strings.TrimPrefix(l, "-r")
			// Path is relative to the current requirement file's dir.
			p = filepath.Join(filepath.Dir(path), p)
			extraPaths = append(extraPaths, p)
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

		inv = append(inv, &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{path},
			Metadata: &Metadata{
				HashCheckingModeValues: hashOptions,
				VersionComparator:      comp,
			},
		})
	}

	return inv, extraPaths, s.Err()
}

// readLine reads a line from the scanner, removes comments and joins it with
// the next line if it ends with a backslash.
func readLine(scanner *bufio.Scanner, builder *strings.Builder) string {
	l := scanner.Text()
	l = removeComments(l)

	if hasEnvVariable(l) {
		// Ignore env variables
		// https://github.com/pypa/pip/blob/72a32e/src/pip/_internal/req/req_file.py#L503
		// TODO(b/286213823): Implement metric
		return ""
	}

	if strings.HasSuffix(l, `\`) {
		builder.WriteString(l[:len(l)-1])
		scanner.Scan()
		return readLine(scanner, builder)
	} else {
		builder.WriteString(l)
	}

	return builder.String()
}

func (e Extractor) exportStats(input *filesystem.ScanInput, err error) {
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
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return pypipurl.MakePackageURL(i)
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "PyPI" }
