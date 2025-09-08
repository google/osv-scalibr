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

// Package bazelmaven extracts maven packages from bazel build files.
package bazelmaven

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/bazelbuild/buildtools/build"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	bazelmavenmeta "github.com/google/osv-scalibr/extractor/filesystem/os/bazelmaven/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/bazelmaven"
)

type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is a Bazel build file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == "BUILD.bazel" ||
		path.Base(api.Path()) == "MODULE.bazel" ||
		path.Base(api.Path()) == "WORKSPACE"
}

// Extract extracts maven packages from the bazel build file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
	}

	// Read all content from the input reader
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error reading input file: %w", err)
	}

	// Use FindAllMavenDependencies to parse the Bazel file and extract Maven dependencies
	dependencies := FindAllMavenDependencies(data)

	var pkgs []*extractor.Package

	// Convert the dependencies to extractor.Package objects
	for _, mavenDeps := range dependencies {
		// should we add the rule name too? the rule which found the deps
		// e.g., maven_install, maven.install, maven.artifact
		// ruleName := rule
		for _, dep := range mavenDeps {
			// Create a package for each Maven dependency
			pkg := &extractor.Package{
				Name:      dep.Name,
				Version:   dep.Version,
				PURLType:  purl.TypeBazelMaven,
				Locations: []string{input.Path},
				Metadata: &bazelmavenmeta.Metadata{
					Name:       dep.Name,
					GroupID:    dep.GroupID,
					ArtifactID: dep.ArtifactID,
					Version:    dep.Version,
				},
			}
			pkgs = append(pkgs, pkg)
		}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// MavenDependency represents a Maven dependency
type MavenDependency struct {
	Name       string // Name of the dependency
	GroupID    string // Maven group ID
	ArtifactID string // Maven artifact ID
	Version    string // Maven version
}

// RuleDependencies maps rule types to their dependencies
type RuleDependencies map[string][]MavenDependency

// FindAllMavenDependencies parses all file sources and returns dependencies by rule type
func FindAllMavenDependencies(input []byte) RuleDependencies {
	// Create a map to hold dependencies by rule type
	allDeps := make(RuleDependencies)

	// Parse the combined file
	f, err := build.Parse("default", input)
	if err != nil {
		panic(err)
	}

	// Find all load statements to track rule sources
	loadMapping := findLoadStatements(f)

	// Find all variables that are assigned from use_extension
	extensionVarsMapping := findExtensionVariables(f)

	// Process all statements
	for _, stmt := range f.Stmt {
		if rule, ok := stmt.(*build.CallExpr); ok {
			r := &build.Rule{Call: rule}
			// Check the type of rule.X to handle both direct rule names "rule_name(...)" and dot expressions ".rule_name(...)"
			switch x := rule.X.(type) {

			case *build.Ident:
				ruleName := x.Name
				switch ruleName {
				case "maven_install":
					//https://github.com/bazel-contrib/rules_jvm_external/blob/1c5cfbf96de595a3e23cf440fb40380cc28c1aea/docs/api.md#maven_install
					// Check if maven_install is loaded from "@rules_jvm_external//:defs.bzl"
					source, exists := loadMapping["maven_install"]
					isMavenInstallFromRulesJvmExt := exists && source == "@rules_jvm_external//:defs.bzl"
					if isMavenInstallFromRulesJvmExt {
						if r.Attr("artifacts") != nil {
							artifacts := GetAttributeArrayValues(r, f, "artifacts")
							// Add a note about the source in the rule name if it's from rules_jvm_external
							allDeps["maven_install"] = append(allDeps["maven_install"], ExtractMavenArtifactInfo(artifacts)...)
						}
						break
					}
				}

			case *build.DotExpr:
				// Check if this is a dot expression (like variable.install)
				// and the "variable" is a assigned by an extension with known specs
				ruleName := x.Name
				if varName, ok := x.X.(*build.Ident); ok {
					if _, exists := extensionVarsMapping[varName.Name]; exists {
						// Check if the base variable is from an extension
						extInfo := extensionVarsMapping[varName.Name]
						// For maven extension, handle artifacts attribute
						if extInfo.BzlFile == "@rules_jvm_external//:extensions.bzl" &&
							extInfo.Name == "maven" {
							switch ruleName {
							// https://github.com/bazel-contrib/rules_jvm_external/blob/1c5cfbf96de595a3e23cf440fb40380cc28c1aea/docs/bzlmod-api.md#maven
							case "install":
								if artifactsAttr := r.Attr("artifacts"); artifactsAttr != nil {
									artifacts := GetAttributeArrayValues(r, f, "artifacts")
									allDeps["maven.install"] = append(allDeps["maven.install"], ExtractMavenArtifactInfo(artifacts)...)
								}
							case "artifact":
								// A single artifact
								if r.Attr("group") != nil && r.Attr("artifact") != nil && r.Attr("version") != nil {
									group := GetAttributeStringValue(r, f, "group")
									artifact := GetAttributeStringValue(r, f, "artifact")
									version := GetAttributeStringValue(r, f, "version")
									allDeps["maven.artifact"] = append(allDeps["maven.artifact"], MavenDependency{
										Name:       group + ":" + artifact + ":" + version,
										GroupID:    group,
										ArtifactID: artifact,
										Version:    version,
									})
								}
							}
						}
					}
				}
			}
		}
	}

	return allDeps
}

// ExtractMavenArtifactInfo extracts Maven coordinates from artifact strings like "org.jetbrains.kotlin:kotlin-stdlib:1.7.10"
func ExtractMavenArtifactInfo(artifacts []string) []MavenDependency {
	var deps []MavenDependency

	for _, artifact := range artifacts {
		parts := strings.Split(artifact, ":")

		dep := MavenDependency{
			Name: artifact,
		}

		if len(parts) >= 3 {
			dep.GroupID = parts[0]
			dep.ArtifactID = parts[1]
			dep.Version = parts[2]
		}

		deps = append(deps, dep)
	}

	return deps
}
