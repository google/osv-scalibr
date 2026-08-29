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

// Package setupcfg extracts Python package dependencies from setuptools
// declarative setup.cfg files. It parses the [options] install_requires and
// [options.extras_require] sections and emits PyPI PURLs for valid PEP 508
// dependency entries.
//
// See https://setuptools.pypa.io/en/latest/userguide/declarative_config.html
// and https://packaging.python.org/en/latest/specifications/dependency-specifiers/.
package setupcfg

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/setupcfg"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will parse.
	defaultMaxFileSizeBytes = 10 * units.MiB

	sectionOptions       = "options"
	sectionOptionsExtras = "options.extras_require"
	keyInstallRequires   = "install_requires"
)

var (
	// reValidPkg matches a valid (PEP 503 normalized) package name.
	// https://packaging.python.org/en/latest/specifications/name-normalization/
	reValidPkg = regexp.MustCompile(`(?i)^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`)
	// reExtras matches extras brackets, e.g. "pkg[extra1,extra2]".
	reExtras = regexp.MustCompile(`\[[^\[\]]*\]`)
	// reComment matches an inline comment introduced by whitespace + # (or a full-line comment).
	reComment = regexp.MustCompile(`(^|\s+)#.*$`)
	// reSpaceOps collapses spaces around comparator characters so PEP 508
	// allows "pkg > 1.0"; names keep their spaces (which makes them invalid).
	reSpaceOps = regexp.MustCompile(`\s*([<>=~!])\s*`)
	// reUnsupportedConstraints matches version constraints we don't reduce to a single
	// lowest version: wildcards, less-than, greater-than (not >=), not-equal, and
	// comma-separated multiple specs. Matching such entries emits the package
	// identity without a version instead of dropping the dependency.
	reUnsupportedConstraints = regexp.MustCompile(`\*|<[^=]|>[^=]|,|!=`)
	// reEnvVar matches environment variable / template interpolations such as ${VAR}
	// or %(VAR)s that setuptools can expand at build time.
	reEnvVar = regexp.MustCompile(`\$\{[A-Za-z0-9_]+\}|%\([A-Za-z0-9_]+\)s`)
	// reURLScheme matches a leading URL/VCS scheme such as git+https://, file:, attr:.
	reURLScheme = regexp.MustCompile(`(?i)^[A-Za-z][A-Za-z0-9+.-]*:`)
)

// Extractor extracts python packages from setup.cfg files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a setup.cfg extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
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

// FileRequired returns true if the specified file is a setup.cfg file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "setup.cfg" {
		return false
	}

	fileinfo, err := api.Stat()
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
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from setup.cfg files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(ctx, input)

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

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	// First pass: read all lines so we can look ahead for multi-line continuation
	// values (setuptools allows indented continuation lines under a key).
	var lines []string
	s := bufio.NewScanner(input.Reader)
	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}
		lines = append(lines, s.Text())
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("error while scanning setup.cfg file: %w", err)
	}

	var pkgs []*extractor.Package
	currentSection := ""
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		trimmed := strings.TrimSpace(raw)

		// Skip blank lines and full-line comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		// Section header, e.g. "[options]" or "[options.extras_require]".
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentSection = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}

		switch currentSection {
		case sectionOptions:
			// Only install_requires is a dependency list under [options].
			key, value, contLines, nextIdx := parseKeyValue(lines, i)
			if !strings.EqualFold(key, keyInstallRequires) {
				i = nextIdx - 1
				continue
			}
			pkgs = append(pkgs, parseRequirementLines(value, contLines, "", input.Path)...)
			i = nextIdx - 1
		case sectionOptionsExtras:
			// Each key under [options.extras_require] is an extras group whose
			// value is a list of requirements.
			group, value, contLines, nextIdx := parseKeyValue(lines, i)
			pkgs = append(pkgs, parseRequirementLines(value, contLines, group, input.Path)...)
			i = nextIdx - 1
		}
	}

	return pkgs, nil
}

// parsedContLine is a single continuation requirement entry with its source line number.
type parsedContLine struct {
	text string
	line int
}

// parseKeyValue reads a "key = value" line at index i and gathers any indented
// continuation lines that follow it. It returns the key, the inline value (if
// any), the list of continuation requirement lines (with their 1-based line
// numbers), and the index of the next line to process.
func parseKeyValue(lines []string, i int) (key, inline string, cont []parsedContLine, nextIdx int) {
	raw := lines[i]
	key, inline, _ = strings.Cut(raw, "=")
	key = strings.TrimSpace(key)
	inline = strings.TrimSpace(inline)

	idx := i + 1
	// setuptools multi-line values are continuation lines that begin with
	// whitespace. A blank line or a non-indented line ends the value.
	for idx < len(lines) {
		next := lines[idx]
		tNext := strings.TrimSpace(next)
		if tNext == "" {
			// A blank line terminates a multi-line value but is otherwise
			// harmless; stop collecting continuation lines here.
			break
		}
		if next[0] != ' ' && next[0] != '\t' {
			// Non-indented line: belongs to the next key/section.
			break
		}
		cont = append(cont, parsedContLine{text: tNext, line: idx + 1})
		idx++
	}
	return key, inline, cont, idx
}

// parseRequirementLines converts the inline value and continuation lines into
// packages. The inline value is attributed to the key's own line; continuation
// lines keep their own line numbers. depGroup is the extras_require group name
// (empty for install_requires).
func parseRequirementLines(inline string, cont []parsedContLine, depGroup, path string) []*extractor.Package {
	var pkgs []*extractor.Package

	// The inline portion of install_requires/extras_require is usually empty
	// (the entries live on continuation lines), but setuptools permits a
	// single inline entry too, e.g. "install_requires = requests>=2.0".
	if inline != "" {
		// We don't have a precise line for the inline value; attribute it to
		// the first continuation line if present, otherwise skip line tracking.
		line := 0
		if len(cont) > 0 {
			line = cont[0].line - 1
		}
		if p := parseRequirement(inline, path, line, depGroup); p != nil {
			pkgs = append(pkgs, p)
		}
	}

	for _, c := range cont {
		if p := parseRequirement(c.text, path, c.line, depGroup); p != nil {
			pkgs = append(pkgs, p)
		}
	}
	return pkgs
}

// parseRequirement parses a single PEP 508-style requirement string and returns
// a Package, or nil if the entry should be skipped (empty, commented, dynamic
// source, invalid name, or unsupported form).
func parseRequirement(s, path string, line int, depGroup string) *extractor.Package {
	// Strip inline comments.
	s = reComment.ReplaceAllString(s, "")
	// Drop environment markers (everything after ';'). We do not evaluate them.
	s = strings.SplitN(s, ";", 2)[0]
	// Drop extras brackets, e.g. "pkg[extra]" -> "pkg".
	s = reExtras.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	// Skip dynamic / indirect dependency sources.
	if isDynamicSource(s) {
		return nil
	}

	name, version, comp := getLowestVersion(s)
	if name == "" || !isValidPackage(name) {
		return nil
	}
	if version == "" && comp != "" {
		// A comparator with no version is malformed.
		return nil
	}

	md := &Metadata{VersionComparator: comp}
	if depGroup != "" {
		md.DepGroup = depGroup
	}

	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypePyPi,
		Location: extractor.LocationFromPathAndLine(filepath.ToSlash(path), line),
		Metadata: md,
	}
}

// isDynamicSource reports whether the requirement string refers to a dynamic or
// indirect dependency source that this extractor does not resolve: file:/
// attr: directives, environment-variable/template values, local paths, VCS/URL
// schemes, and editable installs.
func isDynamicSource(s string) bool {
	// Editable install flag, e.g. "-e ./local/pkg" or "-e git+https://...".
	if strings.HasPrefix(s, "-e ") || s == "-e" {
		return true
	}
	// URL / VCS / directive schemes: file:, attr:, http(s)://, git+..., hg+...,
	// svn+..., bzr+..., git://, etc.
	if reURLScheme.MatchString(s) {
		return true
	}
	// Environment variable / template interpolation.
	if reEnvVar.MatchString(s) {
		return true
	}
	// Local filesystem paths (relative or absolute), e.g. "./pkg", "../pkg",
	// "/abs/path". A bare "." or ".." alone is not a package name.
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "/") {
		return true
	}
	return false
}

// getLowestVersion extracts the package name, version, and comparator from a
// requirement string. For supported comparators (===, ==, >=, <=, ~=) it
// returns the version that appears in the spec. For unsupported constraints
// (wildcards, <, !=, comma-separated specs) it returns the name with an empty
// version so the package is still listed for dependency resolution.
func getLowestVersion(s string) (name, version, comparator string) {
	// PEP 508 permits spaces around comparators; normalize those (and only
	// those) so the regex and separator checks behave the same for
	// "pkg > 1.0" and "pkg>1.0" while malformed names with spaces stay invalid.
	s = reSpaceOps.ReplaceAllString(s, "$1")
	if reUnsupportedConstraints.FindString(s) != "" {
		return nameFromRequirement(s), "", ""
	}

	separators := []string{"===", "==", ">=", "<=", "~="}
	for _, sep := range separators {
		if strings.Contains(s, sep) {
			t := strings.SplitN(s, sep, 2)
			if len(t) != 2 {
				return "", "", ""
			}
			return strings.TrimSpace(t[0]), strings.TrimSpace(t[1]), sep
		}
	}
	// No comparator: bare package name.
	return strings.TrimSpace(s), "", ""
}

func nameFromRequirement(s string) string {
	for _, sep := range []string{"===", "==", ">=", "<=", "~=", "!=", "<", ">"} {
		s, _, _ = strings.Cut(s, sep)
	}
	return strings.TrimSpace(s)
}

func isValidPackage(s string) bool {
	return reValidPkg.MatchString(s)
}
