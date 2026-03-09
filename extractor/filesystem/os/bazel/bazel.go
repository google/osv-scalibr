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

// Package bazel extracts packages from bazel build files.
package bazel

import (
	"context"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/bazelbuild/buildtools/build"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	bazelmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/bazel/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/bazel"
)

// Extractor extracts packages from bazel build files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

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
	return slices.Contains([]string{"BUILD.bazel", "MODULE.bazel", "WORKSPACE"}, path.Base(api.Path()))
}

// Extract extracts packages from the bazel build file.
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

	// Parse the Bazel file once for all extractors
	f, err := build.Parse("default", data)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to parse Bazel file: %w", err)
	}

	var pkgs []*extractor.Package

	// Extract Maven dependencies
	mavenPkgs, err := extractMavenPackages(ctx, e, f, input)
	if err != nil {
		return inventory.Inventory{}, err
	}
	pkgs = append(pkgs, mavenPkgs...)

	// Extract Go dependencies
	goPkgs, err := extractGoPackages(ctx, e, f, input)
	if err != nil {
		return inventory.Inventory{}, err
	}
	pkgs = append(pkgs, goPkgs...)

	return inventory.Inventory{Packages: pkgs}, nil
}

// extractMavenPackages extracts Maven packages from the parsed Bazel file.
func extractMavenPackages(ctx context.Context, e Extractor, f *build.File, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	dependencies := findAllMavenDependenciesFromFile(f)

	var pkgs []*extractor.Package

	for ruleName, mavenDeps := range dependencies {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}
		for _, dep := range mavenDeps {
			pkg := &extractor.Package{
				Name:      dep.Name,
				Version:   dep.Version,
				PURLType:  purl.TypeMaven,
				Locations: []string{input.Path},
				Metadata: &bazelmetadata.MavenMetadata{
					Name:       dep.Name,
					GroupID:    dep.GroupID,
					ArtifactID: dep.ArtifactID,
					Version:    dep.Version,
					RuleName:   ruleName,
				},
			}
			pkgs = append(pkgs, pkg)
		}
	}

	return pkgs, nil
}

// goRuleLoadPaths lists the known load paths for rules_go rule definitions.
var goRuleLoadPaths = []string{
	"@rules_go//go:def.bzl",
	"@rules_go//docs/go/core:rules.bzl",
}

// goRulesWithDeps lists the rules_go rule names that have a "deps" attribute
// containing Go dependency labels.
var goRulesWithDeps = []string{"go_library", "go_binary", "go_test", "go_path", "go_source"}

// extractGoPackages extracts Go packages from rules loaded via rules_go load paths.
// It looks for go_library, go_binary, go_test, go_path, and go_source rules
// and extracts their "deps" attribute values.
func extractGoPackages(ctx context.Context, e Extractor, f *build.File, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
	}

	var pkgs []*extractor.Package

	for _, loadPath := range goRuleLoadPaths {
		results := FindLoadedRuleAttributesFromFile(f, loadPath, "deps")
		for _, result := range results {
			if !slices.Contains(goRulesWithDeps, result.RuleName) {
				continue
			}
			for _, dep := range result.Values {
				pkg := &extractor.Package{
					Name:      dep,
					PURLType:  purl.TypeGolang,
					Locations: []string{input.Path},
					Metadata: &bazelmetadata.GoMetadata{
						RuleName: result.RuleName,
					},
				}
				pkgs = append(pkgs, pkg)
			}
		}
	}

	return pkgs, nil
}

// RuleDependencies maps rule types to their dependencies
type RuleDependencies map[string][]bazelmetadata.MavenMetadata

// findAllMavenDependenciesFromFile extracts Maven dependencies from an already-parsed Bazel file.
func findAllMavenDependenciesFromFile(f *build.File) RuleDependencies {
	// Create a map to hold dependencies by rule type
	allDeps := make(RuleDependencies)

	// Find all load statements to track rule sources
	loadMapping := findLoadStatements(f)

	// Find all variables that are assigned from use_extension
	extensionVarsMapping := findExtensionVariables(f)

	// Process all statements
	for _, stmt := range f.Stmt {
		rule, ok := stmt.(*build.CallExpr)
		if !ok {
			continue
		}
		r := &build.Rule{Call: rule}
		// Check the type of rule.X to handle both direct rule names "rule_name(...)" and dot expressions ".rule_name(...)"
		switch x := rule.X.(type) {
		case *build.Ident:
			processIdentRule(x, r, f, loadMapping, allDeps)
		case *build.DotExpr:
			processDotExprRule(x, r, f, extensionVarsMapping, allDeps)
		}
	}

	return allDeps
}

// processIdentRule handles direct rule name calls (e.g. "maven_install(...)").
// It checks whether the rule is loaded from a known source and extracts artifacts accordingly.
func processIdentRule(x *build.Ident, r *build.Rule, f *build.File, loads loadMapping, allDeps RuleDependencies) {
	if x.Name == "maven_install" {
		source, exists := loads["maven_install"]
		isMavenInstallFromRulesJvmExt := exists && source == "@rules_jvm_external//:defs.bzl"
		if isMavenInstallFromRulesJvmExt {
			if r.Attr("artifacts") != nil {
				artifacts := getAttributeArrayValues(r, f, "artifacts")
				allDeps["maven_install"] = append(allDeps["maven_install"], ExtractMavenArtifactInfo(artifacts)...)
			}
		}
	}
}

// processDotExprRule handles dot-expression rule calls (e.g. "maven.install(...)").
// It resolves the base variable through the extension variable mapping and extracts
// Maven dependencies for known extension methods like "install" and "artifact".
func processDotExprRule(x *build.DotExpr, r *build.Rule, f *build.File, extensionVars map[string]extensionInfo, allDeps RuleDependencies) {
	varName, ok := x.X.(*build.Ident)
	if !ok {
		return
	}
	extInfo, exists := extensionVars[varName.Name]
	if !exists {
		return
	}
	// Only handle the maven extension from rules_jvm_external
	if extInfo.BzlFile != "@rules_jvm_external//:extensions.bzl" || extInfo.Name != "maven" {
		return
	}

	switch x.Name {
	// https://github.com/bazel-contrib/rules_jvm_external/blob/1c5cfbf96de595a3e23cf440fb40380cc28c1aea/docs/bzlmod-api.md#maven
	case "install":
		if r.Attr("artifacts") != nil {
			artifacts := getAttributeArrayValues(r, f, "artifacts")
			allDeps["maven.install"] = append(allDeps["maven.install"], ExtractMavenArtifactInfo(artifacts)...)
		}
	case "artifact":
		if r.Attr("group") != nil && r.Attr("artifact") != nil && r.Attr("version") != nil {
			group := getAttributeStringValue(r, f, "group")
			artifact := getAttributeStringValue(r, f, "artifact")
			version := getAttributeStringValue(r, f, "version")
			allDeps["maven.artifact"] = append(allDeps["maven.artifact"], bazelmetadata.MavenMetadata{
				Name:       group + ":" + artifact,
				GroupID:    group,
				ArtifactID: artifact,
				Version:    version,
			})
		}
	}
}

// ExtractMavenArtifactInfo extracts Maven coordinates from artifact strings like "org.jetbrains.kotlin:kotlin-stdlib:1.7.10"
func ExtractMavenArtifactInfo(artifacts []string) []bazelmetadata.MavenMetadata {
	var deps []bazelmetadata.MavenMetadata

	for _, artifact := range artifacts {
		parts := strings.Split(artifact, ":")

		dep := bazelmetadata.MavenMetadata{}
		dep.Name = parts[0] + ":" + parts[1]

		if len(parts) >= 3 {
			dep.GroupID = parts[0]
			dep.ArtifactID = parts[1]
			dep.Version = parts[2]
		}

		deps = append(deps, dep)
	}

	return deps
}
