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

// Package pomxml extracts pom.xml files.
package pomxml

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"deps.dev/util/maven"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/internal/mavenutil"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml/internal/linetracker"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/pomxml"
)

// "Constant" at the top to compile this regex only once.
var (
	versionRequirementReg = regexp.MustCompile(`[[(]?(.*?)(?:,|[)\]]|$)`)
)

func parseResolvedVersion(version maven.String) string {
	results := versionRequirementReg.FindStringSubmatch(string(version))
	// First capture group will always exist, but might be empty, therefore the slice will always
	// have a length of 2.
	if results == nil || results[1] == "" {
		return ""
	}

	return results[1]
}

// Extractor extracts Maven packages from pom.xml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Maven POM lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pom.xml" || filepath.Ext(api.Path()) == ".pom"
}

// Extract extracts packages from pom.xml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read input: %w", err)
	}

	var project *maven.Project

	if err := datasource.NewMavenDecoder(bytes.NewReader(content)).Decode(&project); err != nil {
		err := fmt.Errorf("could not extract pom from %s: %w", input.Path, err)
		log.Errorf("%v", err)
		return inventory.Inventory{}, err
	}

	// Capture line numbers before Interpolate() and MergeParents().
	//
	// Interpolate() and MergeParents() will:
	//  - Resolve variables (e.g., ${spring.version} into 6.0.0)
	//  - Merge dependencies from parent POMs
	//
	// After these steps, the resolved dependencies in memory will no longer match the raw text in
	// the file, making it impossible to find where they were originally defined by simple string
	// matching.
	rawDeps := linetracker.RawDependencyLinesList(content)

	if err := project.Interpolate(); err != nil {
		err := fmt.Errorf("failed to interpolate pom for %s in %s: %w", project.Name, input.Path, err)
		log.Errorf("%v", err)
		return inventory.Inventory{}, err
	}

	// We'll map final dependencies to rawDeps after ProcessDependencies.
	// We also find the line number of the <parent> tag. If we fail to find a specific
	// line number for a dependency (e.g., because it was inherited from a parent POM
	// and thus doesn't exist in this file's raw XML), we will fallback to attributing
	parentLine := linetracker.ParentLine(content)

	// Merging parents data by parsing local parent pom.xml.
	if err := mavenutil.MergeParents(ctx, project.Parent, project, mavenutil.Options{
		Input:              input,
		AllowLocal:         true,
		InitialParentIndex: 1,
	}); err != nil {
		err := fmt.Errorf("failed to merge parents for %s in %s: %w", project.Name, input.Path, err)
		log.Errorf("%v", err)
		return inventory.Inventory{}, err
	}
	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		// There is no network access so return an empty list of dependency management.
		return maven.DependencyManagement{}, nil
	})

	details := map[string]*extractor.Package{}

	// Keep track of which raw dependencies have been used to prevent wildcard hijacking.
	usedRawDeps := make(map[int]bool)

	for _, dep := range project.Dependencies {
		g, a, found := strings.Cut(dep.Name(), ":")
		if !found {
			err := fmt.Errorf("invalid package name %q for %s in %s", dep.Name(), project.Name, input.Path)
			log.Errorf("%v", err)
			return inventory.Inventory{}, err
		}

		depType := ""
		if dep.Type != "jar" {
			depType = string(dep.Type)
		}

		metadata := javalockfile.Metadata{
			ArtifactID:   a,
			GroupID:      g,
			Type:         depType,
			Classifier:   string(dep.Classifier),
			DepGroupVals: []string{},
		}

		lineNum := linetracker.FindLineNumber(linetracker.FindLineNumberArgs{
			GroupID:     g,
			ArtifactID:  a,
			Version:     string(dep.Version),
			DepType:     depType,
			Classifier:  string(dep.Classifier),
			RawDeps:     rawDeps,
			UsedRawDeps: usedRawDeps,
			ParentLine:  parentLine,
			InputPath:   input.Path,
		})

		pkgDetails := &extractor.Package{
			Name:     dep.Name(),
			Version:  parseResolvedVersion(dep.Version),
			PURLType: purl.TypeMaven,
			Location: extractor.LocationFromPathAndLine(filepath.ToSlash(input.Path), lineNum),
			Metadata: &metadata,
		}
		if scope := strings.TrimSpace(string(dep.Scope)); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			metadata.DepGroupVals = []string{scope}
		}
		details[dep.Name()] = pkgDetails
	}

	return inventory.Inventory{Packages: slices.Collect(maps.Values(details))}, nil
}

var _ filesystem.Extractor = Extractor{}
