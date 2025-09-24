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

// Package pomxml extracts pom.xml files.
package pomxml

import (
	"context"
	"encoding/xml"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"deps.dev/util/maven"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/internal/mavenutil"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
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
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: plugin.NetworkOffline}
}

// FileRequired returns true if the specified file matches Maven POM lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pom.xml" || filepath.Ext(api.Path()) == ".pom"
}

// Extract extracts packages from pom.xml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var project *maven.Project

	if err := xml.NewDecoder(input.Reader).Decode(&project); err != nil {
		err := fmt.Errorf("could not extract pom from %s: %w", input.Path, err)
		log.Errorf(err.Error())
		return inventory.Inventory{}, err
	}
	if err := project.Interpolate(); err != nil {
		err := fmt.Errorf("failed to interpolate pom for %s in %s: %w", project.Name, input.Path, err)
		log.Errorf(err.Error())
		return inventory.Inventory{}, err
	}

	// Merging parents data by parsing local parent pom.xml.
	if err := mavenutil.MergeParents(ctx, project.Parent, project, mavenutil.Options{
		Input:              input,
		AllowLocal:         true,
		InitialParentIndex: 1,
	}); err != nil {
		err := fmt.Errorf("failed to merge parents for %s in %s: %w", project.Name, input.Path, err)
		log.Errorf(err.Error())
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

	for _, dep := range project.Dependencies {
		g, a, found := strings.Cut(dep.Name(), ":")
		if !found {
			err := fmt.Errorf("invalid package name %q for %s in %s", dep.Name(), project.Name, input.Path)
			log.Errorf(err.Error())
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
		pkgDetails := &extractor.Package{
			Name:      dep.Name(),
			Version:   parseResolvedVersion(dep.Version),
			PURLType:  purl.TypeMaven,
			Locations: []string{input.Path},
			Metadata:  &metadata,
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
