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
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/purl"
)

// Extractor extracts python packages from requirements.txt files.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return "python/requirements" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches python Metadata file
// patterns.
func (e Extractor) FileRequired(path string, _ fs.FileInfo) bool {
	// For Windows
	path = filepath.ToSlash(path)
	return filepath.Ext(path) == ".txt" && strings.Contains(filepath.Base(path), "requirements")
}

// Extract extracts packages from requirements files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	inventory := []*extractor.Inventory{}
	s := bufio.NewScanner(input.Reader)
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

		if strings.HasPrefix("-", l) {
			// Global options are not implemented
			// https://pip.pypa.io/en/stable/reference/requirements-file-format/#global-options
			// The -r might be the most interesting, as it includes other requirements files.
			// TODO(b/286213823): Implement metric
			continue
		}

		if isVersionRanges(l) {
			// Ignore version ranges
			// TODO(b/286213823): Implement metric
			continue
		}

		name, version := getPinnedVersion(l)
		if name == "" || version == "" {
			// Either empty
			continue
		}
		if !isValidPackage(name) {
			// TODO(b/286213823): Implement Metric
			continue
		}

		var metadata any
		if len(hashOptions) > 0 {
			metadata = &Metadata{HashCheckingModeValues: hashOptions}
		}
		inventory = append(inventory, &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{input.Path},
			Metadata:  metadata,
		})
	}

	return inventory, s.Err()
}

// https://github.com/pypa/pip/blob/72a32e/src/pip/_internal/req/req_file.py#L492
func removeComments(s string) string {
	return regexp.MustCompile(`(^|\s+)#.*$`).ReplaceAllString(s, "")
}

func getPinnedVersion(s string) (name, version string) {
	t := []string{}
	if strings.Contains(s, "===") {
		t = strings.SplitN(s, "===", 2)
	} else if strings.Contains(s, "==") {
		t = strings.SplitN(s, "==", 2)
	}

	if len(t) != 2 {
		return "", ""
	}

	return t[0], t[1]
}

func isVersionRanges(s string) bool {
	return regexp.MustCompile(`\*|>|<|,`).FindString(s) != ""
}

func removeWhiteSpaces(s string) string {
	return regexp.MustCompile(`[ \t\r]`).ReplaceAllString(s, "")
}

func ignorePythonSpecifier(s string) string {
	return strings.SplitN(s, ";", 2)[0]
}

func isValidPackage(s string) bool {
	return regexp.MustCompile(`^\w(\w|-)+$`).MatchString(s)
}

func removeExtras(s string) string {
	return regexp.MustCompile(`\[[^\[\]]*\]`).ReplaceAllString(s, "")
}

func hasEnvVariable(s string) bool {
	return regexp.MustCompile(`(?P<var>\$\{(?P<name>[A-Z0-9_]+)\})`).FindString(s) != ""
}

// splitPerRequirementOptions removes from the input all text after the first per requirement option
// and returns the remaining input along with the values of the --hash options. See the documentation
// in https://pip.pypa.io/en/stable/reference/requirements-file-format/#per-requirement-options.
func splitPerRequirementOptions(s string) (string, []string) {
	textAfterFirstOptionInclusive := regexp.MustCompile(`(?:--hash|--global-option|--config-settings|-C).*`)
	hashOption := regexp.MustCompile(`--hash=(.+?)(?:$|\s)`)
	hashes := []string{}
	for _, hashOptionMatch := range hashOption.FindAllStringSubmatch(s, -1) {
		hashes = append(hashes, hashOptionMatch[1])
	}
	return textAfterFirstOptionInclusive.ReplaceAllString(s, ""), hashes
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    strings.ToLower(i.Name),
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
