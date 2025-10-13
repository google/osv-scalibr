// Copyright 2025 Google LLC
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

// Package mariadb returns a list of secret mariadb credentials found in *.cnf and *.ini mariadb files
package mariadb

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "secrets/mariadb"
)

var (
	keyValuePattern = regexp.MustCompile(`^\s*([^:=\s]+)\s*[:=]\s*(.+)$`)
)

// Extractor extracts mariadb secret credentials.
type Extractor struct {
	visited map[string]struct{}
}

// New returns a new instance of the extractor.
func New() filesystem.Extractor {
	return &Extractor{
		visited: map[string]struct{}{},
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file contains mariadb config information
// - ref: https://mariadb.com/docs/connectors/mariadb-connector-c/configuring-mariadb-connectorc-with-option-files
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	for _, s := range []string{"my.cnf", "my.ini", "mariadb.cnf", "mariadb.ini"} {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	return false
}

// Extract returns a list of secret mariadb credentials
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	i := inventory.Inventory{}

	sections, err := e.includeFile(ctx, input, input.Path)
	if err != nil {
		return i, err
	}

	for _, s := range sections {
		if !isSecret(s) {
			continue
		}
		i.Secrets = append(i.Secrets, &inventory.Secret{
			Secret:   *s,
			Location: input.Path,
		})
	}

	return i, nil
}

// includeFile recursively extract sections from a config file
func (e *Extractor) includeFile(ctx context.Context, input *filesystem.ScanInput, path string) ([]*Credentials, error) {

	// Prevent circular includes.
	if _, seen := e.visited[path]; seen {
		return nil, nil
	}
	e.visited[path] = struct{}{}

	f, err := input.FS.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	curSection := ""
	sections := map[string]*Credentials{}
	scanner := bufio.NewScanner(f)

	// keeping included sections separate instead of overwriting
	// since file are not traversed in a particular order
	included := []*Credentials{}

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		line := strings.TrimSpace(scanner.Text())

		// skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// include a file or a folder
		if strings.HasPrefix(line, "!include") {
			section, err := e.include(ctx, input, line)
			if err != nil {
				return nil, err
			}
			included = append(included, section...)
			continue
		}

		// new section encountered
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			curSection = strings.Trim(line, "[]")
			if _, ok := sections[curSection]; !ok {
				sections[curSection] = &Credentials{Section: curSection}
			}
		}

		// add key value pair to the current section
		matches := keyValuePattern.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		key, value := matches[1], matches[2]
		// If the key is not related to credentials, ignore it silently
		_ = sections[curSection].setField(key, value)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return slices.Concat(included, slices.Collect(maps.Values(sections))), nil
}

// isSecret returns true if a set of credentials contains a secret
func isSecret(c *Credentials) bool {
	return c.Password != "" && c.User != "healthcheck"
}

// include call includeDir or includeFile depending on the prefix
func (e *Extractor) include(ctx context.Context, input *filesystem.ScanInput, line string) ([]*Credentials, error) {
	if after, ok := strings.CutPrefix(line, "!includedir"); ok {
		sections, err := e.includeDir(ctx, input, strings.TrimSpace(after))
		return sections, err
	}
	if after, ok := strings.CutPrefix(line, "!include"); ok {
		sections, err := e.includeFile(ctx, input, strings.TrimSpace(after))
		return sections, err
	}
	return nil, fmt.Errorf("unknown include prefix in %q", line)
}

// includeDir recursively loads .cnf and .ini files from a specified directory directory.
func (e *Extractor) includeDir(ctx context.Context, input *filesystem.ScanInput, dir string) ([]*Credentials, error) {
	entries, err := fs.ReadDir(input.FS, dir)
	if err != nil {
		return nil, err
	}

	res := []*Credentials{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if !strings.HasSuffix(path, ".cnf") && !strings.HasSuffix(path, ".ini") {
			continue
		}
		sections, err := e.includeFile(ctx, input, path)
		if err != nil {
			return nil, err
		}
		res = append(res, sections...)
	}
	return res, nil
}
