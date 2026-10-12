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
	javascriptmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/metadata"
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
	name := name(pkg, eco)
	return NormalizedPackage{
		Name:      name,
		Ecosystem: eco,
		Version:   version(pkg, name, eco),
		Commit:    commit(pkg),
	}
}

func name(pkg *extractor.Package, eco osvecosystem.Parsed) string {
	// Reconstruct package name with PURL namespace
	name := purlToName(pkg.Name, pkg.PURL(), eco)

	// Patch Go package to stdlib
	if eco.Ecosystem == osvconstants.EcosystemGo && name == "go" {
		return "stdlib"
	}

	// Python normalization
	if eco.Ecosystem == osvconstants.EcosystemPyPI {
		return strings.ToLower(pythonNormalizationRegex.ReplaceAllLiteralString(name, "-"))
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
			return name + "/" + match[1]
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

	return name
}

// purlToName formats a package name using PURL namespace metadata according to ecosystem naming conventions.
func purlToName(pkgName string, p *purl.PackageURL, eco osvecosystem.Parsed) string {
	if p == nil || p.Namespace == "" {
		return pkgName
	}

	// OS distro namespaces should not prefix package name
	if isOSPURLType(p.Type) {
		return pkgName
	}

	purlNamespace := p.Namespace
	switch eco.Ecosystem {
	case osvconstants.EcosystemMaven:
		if !strings.HasPrefix(pkgName, purlNamespace+":") {
			return purlNamespace + ":" + pkgName
		}
	default:
		// PURL namespaces may be lowercased (e.g. Go), while pkgName keeps its original case.
		if !strings.HasPrefix(strings.ToLower(pkgName), strings.ToLower(purlNamespace)+"/") {
			return purlNamespace + "/" + pkgName
		}
	}

	return pkgName
}

func isOSPURLType(purlType string) bool {
	switch purlType {
	case purl.TypeDebian,
		purl.TypeApk,
		purl.TypeRPM,
		purl.TypeAlpm,
		purl.TypeOpkg,
		purl.TypeFlatpak,
		purl.TypeCOS,
		purl.TypeSnap,
		purl.TypePacman,
		purl.TypePortage,
		purl.TypeNix,
		purl.TypeDHI:

		return true
	default:
		return false
	}
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

// rhelFamilyEpochEcosystems lists the RPM ecosystems whose OSV records encode
// the package epoch (verified against api.osv.dev). Others (e.g. openEuler)
// store epoch-less records, so prepending an epoch there would hide real
// vulnerabilities; add entries only once epoch-encoding is confirmed.
var rhelFamilyEpochEcosystems = map[string]bool{
	"Red Hat":     true,
	"AlmaLinux":   true,
	"Rocky Linux": true,
}

// ecosystemEncodesEpoch reports whether the ecosystem's OSV records carry the
// RPM epoch, so its version must be epoch-qualified to compare correctly.
func ecosystemEncodesEpoch(ecosystem string) bool {
	distro, _, _ := strings.Cut(ecosystem, ":")
	return rhelFamilyEpochEcosystems[distro]
}

func version(pkg *extractor.Package, name string, eco osvecosystem.Parsed) string {
	// Assume Go stdlib patch version as the latest version
	//
	// This is done because go1.20 and earlier do not support patch
	// version in go.mod file, and will fail to build.
	// However, if we assume patch version as .0, this will cause a lot of
	// false positives. This compromise still allows osv-scanner to pick up
	// when the user is using a minor version that is out-of-support.
	if eco.Ecosystem == osvconstants.EcosystemGo && name == "stdlib" {
		components := strings.Split(pkg.Version, ".")
		if len(components) == 2 {
			return components[0] + "." + components[1] + ".99"
		}
	}

	version := pkg.Version
	// scalibr stores the RPM epoch separately from the version string. For
	// ecosystems whose OSV records encode it, prepend the epoch when non-zero
	// (e.g. "3.2.2-7.el9_6" -> "1:3.2.2-7.el9_6"); otherwise a missing epoch is
	// read as 0 and already-fixed advisories are reported as unfixed.
	if m, ok := pkg.Metadata.(*rpmmetadata.Metadata); ok && m.Epoch > 0 && ecosystemEncodesEpoch(eco.String()) {
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

// IsLocal checks if a package is marked as locally-installed or developed
// (e.g. workspace members or local file dependencies in NPM).
func IsLocal(pkg *extractor.Package) bool {
	if pkg == nil || pkg.Metadata == nil {
		return false
	}
	if m, ok := pkg.Metadata.(interface {
		PackageSource() javascriptmeta.NPMPackageSource
	}); ok {
		return m.PackageSource() == javascriptmeta.Local
	}
	return false
}
