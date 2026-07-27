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

// Package osvutil provides shared utilities for OSV vulnerability matching.
package osvutil

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	archivemetadata "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

var (
	pythonNormalizationRegex = regexp.MustCompile(`[-_.]+`)
	goVersionSuffixRegexp    = regexp.MustCompile(`(v[0-9]+)`)
)

// NormalizedPackage holds the OSV-compatible package metadata.
type NormalizedPackage struct {
	Name      string
	Ecosystem osvecosystem.Parsed
	Version   string
	Commit    string
}

// ParsePackage parses and normalizes package metadata for OSV.
func ParsePackage(pkg *extractor.Package) NormalizedPackage {
	eco := ecosystem(pkg)
	return NormalizedPackage{
		Name:      name(pkg, eco),
		Ecosystem: eco,
		Version:   version(pkg, eco.String()),
		Commit:    commit(pkg),
	}
}

func name(pkg *extractor.Package, eco osvecosystem.Parsed) string {
	// Patch Go package to stdlib
	if eco.Ecosystem == osvconstants.EcosystemGo && pkg.Name == "go" {
		return "stdlib"
	}

	// Python normalization
	if eco.Ecosystem == osvconstants.EcosystemPyPI {
		return strings.ToLower(pythonNormalizationRegex.ReplaceAllLiteralString(pkg.Name, "-"))
	}

	// Maven group:artifact patch
	if metadata, ok := pkg.Metadata.(*archivemetadata.Metadata); ok {
		if metadata.ArtifactID != "" && metadata.GroupID != "" {
			return metadata.GroupID + ":" + metadata.ArtifactID
		}
	}

	// OS package patches
	if metadata, ok := pkg.Metadata.(*dpkgmeta.Metadata); ok {
		if metadata.SourceName != "" {
			return metadata.SourceName
		}
	}
	if metadata, ok := pkg.Metadata.(*apkmeta.Metadata); ok {
		if metadata.OriginName != "" {
			return metadata.OriginName
		}
	}

	// Go major version suffix patch from PURL subpath
	if eco.Ecosystem == osvconstants.EcosystemGo && pkg.PURL() != nil && pkg.PURL().Subpath != "" {
		match := goVersionSuffixRegexp.FindStringSubmatch(pkg.PURL().Subpath)
		if match != nil {
			return pkg.Name + "/" + match[1]
		}
	}

	// Homebrew package with source code repo
	if pkg.PURL() != nil && pkg.PURL().Type == purl.TypeBrew && pkg.SourceCode != nil {
		return strings.ToLower(pkg.SourceCode.Repo)
	}

	// GIT ecosystem with source code repo
	if eco.String() == "GIT" && pkg.SourceCode != nil && pkg.SourceCode.Repo != "" {
		repo := pkg.SourceCode.Repo
		normalized := normalizeRepo(repo)
		if strings.HasPrefix(strings.ToLower(normalized), "github.com/") || strings.HasPrefix(strings.ToLower(normalized), "gitlab.") {
			return strings.ToLower(repo)
		}
		return repo
	}

	return pkg.Name
}

func normalizeRepo(repo string) string {
	repo = strings.TrimPrefix(repo, "https://")
	repo = strings.TrimPrefix(repo, "http://")
	repo = strings.TrimPrefix(repo, "git://")
	return strings.TrimSuffix(repo, ".git")
}

func ecosystem(pkg *extractor.Package) osvecosystem.Parsed {
	eco := pkg.Ecosystem()

	// If ecosystem is empty and the source code repo is set, set ecosystem to GIT
	if eco.Ecosystem == "" && pkg.SourceCode != nil {
		eco = osvecosystem.MustParse("GIT")
	}

	return eco
}

var rhelFamilyEpochEcosystems = map[string]bool{
	"Red Hat":     true,
	"AlmaLinux":   true,
	"Rocky Linux": true,
}

func ecosystemEncodesEpoch(ecosystem string) bool {
	distro, _, _ := strings.Cut(ecosystem, ":")
	return rhelFamilyEpochEcosystems[distro]
}

func version(pkg *extractor.Package, ecosystem string) string {
	version := pkg.Version
	if m, ok := pkg.Metadata.(*rpmmetadata.Metadata); ok && m.Epoch > 0 && ecosystemEncodesEpoch(ecosystem) {
		return strconv.Itoa(m.Epoch) + ":" + version
	}
	return version
}

func commit(pkg *extractor.Package) string {
	if pkg.SourceCode != nil {
		return pkg.SourceCode.Commit
	}
	return ""
}
