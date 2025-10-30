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

// Package dpkgsource provides a way to annotate packages with repository source information.
package dpkgsource

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name of the Annotator
	Name = "misc/dpkg-source"
)

// FetchAptCachePolicy to allow for mocking in testing.
var FetchAptCachePolicy = aptCachePolicy

// Annotator adds repository source context for extracted Debian packages from dpkg extractor.
type Annotator struct{}

// New returns a new Annotator.
func New() annotator.Annotator { return Annotator{} }

// Name returns the name of the annotator.
func (Annotator) Name() string { return Name }

// Version returns the version of the annotator.
func (Annotator) Version() int { return 0 }

// Requirements returns the requirements of the annotator.
func (Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSLinux, RunningSystem: true}
}

// Annotate adds repository source context for extracted Debian packages from dpkg extractor.
func (a Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	// Call apt-cache policy once with all packages.
	dpkgToSources, err := FetchAptCachePolicy(ctx, results.Packages)
	if err != nil {
		return fmt.Errorf("%s halted while fetching apt-cache policy: %w", a.Name(), err)
	}

	// Update package metadata with source information.
	for _, pkg := range results.Packages {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s halted at %q because of context error: %w", a.Name(), input.ScanRoot.Path, err)
		}
		// Only annotate debian packages.
		if pkg.PURLType != purl.TypeDebian {
			continue
		}
		md, ok := pkg.Metadata.(*metadata.Metadata)
		if !ok {
			continue
		}
		// Update dpkg metadata PackageSource field.
		if source, ok := dpkgToSources[pkg.Name]; ok {
			md.PackageSource = source
		} else {
			md.PackageSource = "unknown"
		}
	}

	return nil
}

func aptCachePolicy(ctx context.Context, packages []*extractor.Package) (map[string]string, error) {
	// List all installed Debian package names.
	var pkgNames []string
	for _, pkg := range packages {
		if pkg.PURLType != purl.TypeDebian {
			continue
		}
		pkgNames = append(pkgNames, pkg.Metadata.(*metadata.Metadata).PackageName)
	}

	// Call apt-cache policy once with all package names.
	args := append([]string{"policy"}, pkgNames...)
	cmd := exec.CommandContext(ctx, "apt-cache", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("calling apt-cache policy failed: %w", err)
	}

	// Return packages mapped to package sources.
	return MapPackageToSource(ctx, string(output))
}

// MapPackageToSource parses the output of "apt-cache policy" and returns a map
// from package names to their repository sources.
func MapPackageToSource(ctx context.Context, aptCacheOutput string) (map[string]string, error) {
	// Parse apt-cache policy output and map package names to repository sources.
	dpkgSource := make(map[string]string)
	var pkgName string

	scanner := bufio.NewScanner(strings.NewReader(aptCacheOutput))

	for scanner.Scan() {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}
		// A new package block starts when a line is not indented and begins with package name.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			pkgName = strings.TrimSuffix(line, ":")
		}
		// Installed version is signified by leading '***'.
		if pkgName != "" && strings.HasPrefix(trimmedLine, "***") {
			// Advance scanner to next line to read the top priority source.
			if !scanner.Scan() {
				log.Warnf("dpkg-source: could not find source for package %q, unexpected end of apt-cache policy output", pkgName)
				dpkgSource[pkgName] = "unknown"
				pkgName = ""
				continue
			}
			priorityLine := strings.TrimSpace(scanner.Text())
			// Remove priority number and other information, return the repository source.
			repoSource := strings.Split(priorityLine, " ")
			if len(repoSource) < 2 {
				log.Warnf("dpkg-source: could not parse source for package %q from line: %q", pkgName, priorityLine)
				dpkgSource[pkgName] = "unknown"
				pkgName = ""
				continue
			}
			dpkgSource[pkgName] = repoSource[1]
			// Reset package name string and continue scanning.
			pkgName = ""
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return dpkgSource, nil
}
