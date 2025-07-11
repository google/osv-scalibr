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

package extractor

import (
	hexpurl "github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock/purl"
	gopurl "github.com/google/osv-scalibr/extractor/filesystem/language/golang/purl"
	mavenpurl "github.com/google/osv-scalibr/extractor/filesystem/language/java/purl"
	npmpurl "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/purl"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pypipurl"
	osecosystem "github.com/google/osv-scalibr/extractor/filesystem/os/ecosystem"
	ospurl "github.com/google/osv-scalibr/extractor/filesystem/os/purl"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	cdxpurl "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/purl"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	spdxpurl "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/purl"
	winpurl "github.com/google/osv-scalibr/extractor/standalone/windows/common/purl"
	"github.com/google/osv-scalibr/purl"
)

// toPURL converts a SCALIBR package structure into a package URL.
func toPURL(p *Package) *purl.PackageURL {
	if p.PURLType == "" {
		return nil
	}
	// See if this needs any special type-specific conversion logic.
	if purl := typeSpecificPURL(p); purl != nil {
		return purl
	}
	// All other cases: Set just the name and version.
	return &purl.PackageURL{
		Type:    p.PURLType,
		Name:    p.Name,
		Version: p.Version,
	}
}

func typeSpecificPURL(p *Package) *purl.PackageURL {
	// SPDX and CDX packages can have any PURL type so we first look at the
	// metadata type to identify them.
	switch m := p.Metadata.(type) {
	case *spdxmeta.Metadata:
		return spdxpurl.MakePackageURL(m)
	case *cdxmeta.Metadata:
		return cdxpurl.MakePackageURL(m)
	}

	switch p.PURLType {
	case purl.TypePyPi:
		return pypipurl.MakePackageURL(p.Name, p.Version)
	case purl.TypeMaven:
		return mavenpurl.MakePackageURL(p.Version, p.Metadata)
	case purl.TypeNPM:
		return npmpurl.MakePackageURL(p.Name, p.Version, p.Metadata)
	case purl.TypeGolang:
		return gopurl.MakePackageURL(p.Name, p.Version)
	case purl.TypeHex:
		return hexpurl.MakePackageURL(p.Name, p.Version)
	case purl.TypeDebian, purl.TypeOpkg, purl.TypeFlatpak, purl.TypeApk, purl.TypeCOS, purl.TypeRPM,
		purl.TypeSnap, purl.TypePacman, purl.TypePortage, purl.TypeNix, purl.TypeKernelModule:
		return ospurl.MakePackageURL(p.Name, p.Version, p.PURLType, p.Metadata)
	case "windows":
		return winpurl.MakePackageURL(p.Name, p.Version, p.Metadata)
	}
	return nil
}

// toEcosystem converts a SCALIBR package structure into an OSV ecosystem value
// defined in https://ossf.github.io/osv-schema/#defined-ecosystems
func toEcosystem(p *Package) string {
	switch p.PURLType {
	case purl.TypeDebian, purl.TypeOpkg, purl.TypeApk, purl.TypeRPM,
		purl.TypeSnap, purl.TypePacman, purl.TypePortage, purl.TypeKernelModule:
		return osecosystem.MakeEcosystem(p.Metadata)
	case purl.TypePyPi:
		return "PyPI"
	case purl.TypeMaven:
		return "Maven"
	case purl.TypeNPM:
		return "npm"
	case purl.TypeGolang:
		return "Go"
	case purl.TypeCocoapods:
		return "CocoaPods"
	case purl.TypeConan:
		return "ConanCenter"
	case purl.TypeCran:
		return "CRAN"
	case purl.TypeGem:
		return "RubyGems"
	case purl.TypeNuget:
		return "NuGet"
	case purl.TypeHaskell:
		return "Hackage"
	case purl.TypeHex:
		return "Hex"
	case purl.TypeComposer:
		return "Packagist"
	case purl.TypeCargo:
		return "crates.io"
	case purl.TypePub:
		return "Pub"
	}

	// No Ecosystem defined for this package.
	return ""
}
