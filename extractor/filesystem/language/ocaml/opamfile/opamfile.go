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

// Package opamfile extracts OCaml packages from project .opam manifest files.
package opamfile

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "ocaml/opamfile"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

var fieldStartRegex = regexp.MustCompile(`^([a-zA-Z0-9_+-]+)\s*:\s*(.*)$`)

// Extractor extracts OCaml packages from .opam manifest files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a new instance of the extractor.
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

// FileRequired returns true if the file path matches .opam project manifest files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())
	if base != "opam" && filepath.Ext(base) != ".opam" {
		return false
	}
	fileinfo, err := api.Stat()
	return err == nil && (e.maxFileSizeBytes <= 0 || fileinfo.Size() <= e.maxFileSizeBytes)
}

// Extract extracts packages from the .opam manifest file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages, err := ParseOpamFile(ctx, input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	for _, pkg := range packages {
		pkg.Location = extractor.LocationFromPath(input.Path)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// ParseOpamFile parses an opam manifest file and extracts dependency names.
func ParseOpamFile(ctx context.Context, r io.Reader) ([]*extractor.Package, error) {
	scanner := bufio.NewScanner(r)
	var packages []*extractor.Package
	seen := map[string]bool{}

	var listContent strings.Builder
	inList := false
	bracketDepth := 0
	inBlockComment := false

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s halted due to context error: %w", Name, err)
		}

		line, stillInBlockComment := stripOpamComments(scanner.Text(), inBlockComment)
		inBlockComment = stillInBlockComment
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			continue
		}

		if !inList {
			// Check for new field start.
			match := fieldStartRegex.FindStringSubmatch(trimmed)
			if match == nil {
				continue
			}
			fieldName := match[1]
			if fieldName != "depends" && fieldName != "depopts" {
				continue
			}
			rest := match[2]

			// Check for list start on the same line.
			_, afterBracket, hasBracket := strings.Cut(rest, "[")
			if hasBracket {
				inList = true
				bracketDepth = 1
				if appendListFragment(afterBracket, &listContent, &bracketDepth) {
					packages = appendPackages(packages, extractPackages(listContent.String()), seen)
					listContent.Reset()
					inList = false
				} else {
					listContent.WriteString("\n")
				}
				continue
			}

			// Check for single-string value (opam 1.2 style).
			if pkg := extractQuotedString(rest); pkg != "" && isValidPackageName(pkg) {
				packages = appendPackage(packages, &extractor.Package{
					Name:     pkg,
					Version:  "",
					PURLType: purl.TypeOpam,
				}, seen)
				continue
			}

			// List may start on next line; continue scanning.
			continue
		}

		// In list mode: collect lines until matching ].
		if appendListFragment(line, &listContent, &bracketDepth) {
			packages = appendPackages(packages, extractPackages(listContent.String()), seen)
			listContent.Reset()
			inList = false
		} else {
			listContent.WriteString("\n")
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

// stripOpamComments removes OPAM # line comments and (* block comments *) outside strings.
func stripOpamComments(line string, inBlockComment bool) (string, bool) {
	var out strings.Builder
	inString := false
	escaped := false

	for i := 0; i < len(line); i++ {
		if inBlockComment {
			if i+1 < len(line) && line[i] == '*' && line[i+1] == ')' {
				inBlockComment = false
				i++
			}
			continue
		}

		ch := line[i]
		if inString {
			out.WriteByte(ch)
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			inString = true
			out.WriteByte(ch)
			continue
		}
		if ch == '#' {
			break
		}
		if i+1 < len(line) && ch == '(' && line[i+1] == '*' {
			inBlockComment = true
			i++
			continue
		}
		out.WriteByte(ch)
	}

	return out.String(), inBlockComment
}

// appendListFragment appends list text until the matching top-level closing bracket is found.
func appendListFragment(fragment string, listContent *strings.Builder, bracketDepth *int) bool {
	inString := false
	escaped := false

	for i := range len(fragment) {
		ch := fragment[i]
		if inString {
			listContent.WriteByte(ch)
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			inString = true
			listContent.WriteByte(ch)
			continue
		}
		switch ch {
		case '[':
			*bracketDepth += 1
			listContent.WriteByte(ch)
		case ']':
			*bracketDepth -= 1
			if *bracketDepth == 0 {
				return true
			}
			listContent.WriteByte(ch)
		default:
			listContent.WriteByte(ch)
		}
	}

	return false
}

func appendPackages(packages []*extractor.Package, newPackages []*extractor.Package, seen map[string]bool) []*extractor.Package {
	for _, pkg := range newPackages {
		packages = appendPackage(packages, pkg, seen)
	}
	return packages
}

func appendPackage(packages []*extractor.Package, pkg *extractor.Package, seen map[string]bool) []*extractor.Package {
	if seen[pkg.Name] {
		return packages
	}
	seen[pkg.Name] = true
	return append(packages, pkg)
}

// extractPackages extracts quoted strings at brace-depth 0 from list content.
func extractPackages(text string) []*extractor.Package {
	var packages []*extractor.Package
	braceDepth := 0

	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '{' {
			braceDepth++
		} else if ch == '}' {
			if braceDepth > 0 {
				braceDepth--
			}
		} else if ch == '"' {
			j := i + 1
			for j < len(text) && text[j] != '"' {
				if text[j] == '\\' {
					j += 2
					if j > len(text) {
						j = len(text)
					}
				} else {
					j++
				}
			}
			if j < len(text) {
				s := text[i+1 : j]
				if braceDepth == 0 && isValidPackageName(s) {
					packages = append(packages, &extractor.Package{
						Name:     s,
						Version:  "",
						PURLType: purl.TypeOpam,
					})
				}
			}
			i = j
		}
	}

	return packages
}

// extractQuotedString extracts the first quoted string from text, or "" if none.
func extractQuotedString(text string) string {
	idx := strings.Index(text, "\"")
	if idx == -1 {
		return ""
	}
	end := strings.Index(text[idx+1:], "\"")
	if end == -1 {
		return ""
	}
	return text[idx+1 : idx+1+end]
}

// isValidPackageName filters out pure version numbers and empty strings.
func isValidPackageName(s string) bool {
	if s == "" {
		return false
	}
	// Filter out pure version numbers (all digits and dots), e.g. "1.0", "4.14".
	allDigitsAndDots := true
	for _, c := range s {
		if !((c >= '0' && c <= '9') || c == '.') {
			allDigitsAndDots = false
			break
		}
	}
	return !allDigitsAndDots
}

var _ filesystem.Extractor = Extractor{}
