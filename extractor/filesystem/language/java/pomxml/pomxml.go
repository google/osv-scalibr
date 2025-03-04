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
	"path/filepath"
	"regexp"
	"strings"

	"deps.dev/util/maven"
	"golang.org/x/exp/maps"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/internal/mavenutil"
	"github.com/google/osv-scalibr/inventory"
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
		return "0"
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
	return filepath.Base(api.Path()) == "pom.xml"
}

// Extract extracts packages from pom.xml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var project *maven.Project

	err := xml.NewDecoder(input.Reader).Decode(&project)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}
	if err := project.Interpolate(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to interpolate pom.xml %s: %w", input.Path, err)
	}

	// Merging parents data by parsing local parent pom.xml.
	if err := mavenutil.MergeParents(ctx, project.Parent, project, mavenutil.Options{
		Input:              input,
		AllowLocal:         true,
		InitialParentIndex: 1,
	}); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to merge parents: %w", err)
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
			return inventory.Inventory{}, fmt.Errorf("invalid package name: %s", dep.Name())
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
			Locations: []string{input.Path},
			Metadata:  &metadata,
		}
		if scope := strings.TrimSpace(string(dep.Scope)); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			metadata.DepGroupVals = []string{scope}
		}
		details[dep.Name()] = pkgDetails
	}

	return inventory.Inventory{Packages: maps.Values(details)}, nil
}

// ToPURL converts a package created by this extractor into a PURL.
func (e Extractor) ToPURL(p *extractor.Package) *purl.PackageURL {
	m := p.Metadata.(*javalockfile.Metadata)
	return &purl.PackageURL{
		Type:      purl.TypeMaven,
		Namespace: strings.ToLower(m.GroupID),
		Name:      strings.ToLower(m.ArtifactID),
		Version:   p.Version,
		Qualifiers: purl.QualifiersFromMap(map[string]string{
			purl.Type:       m.Type,
			purl.Classifier: m.Classifier,
		}),
	}
}

// Ecosystem returns the OSV ecosystem ('Maven') of the software extracted by this extractor.
func (e Extractor) Ecosystem(p *extractor.Package) string {
	return "Maven"
}

var _ filesystem.Extractor = Extractor{}
