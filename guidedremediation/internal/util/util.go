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

// Package util implements some utility functions for guided remediation.
package util

import (
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// DepsDevToOSVEcosystem converts a deps.dev resolve.System into an osvschema.Ecosystem.
// Unknown / invalid Systems become the empty ecosystem `osvschema.Ecosystem("")`.
func DepsDevToOSVEcosystem(sys resolve.System) osvschema.Ecosystem {
	switch sys {
	case resolve.Maven:
		return osvschema.EcosystemMaven
	case resolve.NPM:
		return osvschema.EcosystemNPM
	case resolve.PyPI:
		return osvschema.EcosystemPyPI
	case resolve.UnknownSystem:
		fallthrough
	default:
		return ""
	}
}

// OSVToDepsDevEcosystem converts an osvschema.Ecosystem into a deps.dev resolve.System.
// Unknown / invalid Ecosystems become `resolve.UnknownEcosystem`.
func OSVToDepsDevEcosystem(sys osvschema.Ecosystem) resolve.System {
	switch sys {
	case osvschema.EcosystemMaven:
		return resolve.Maven
	case osvschema.EcosystemNPM:
		return resolve.NPM
	case osvschema.EcosystemPyPI:
		return resolve.PyPI
	default:
		return resolve.UnknownSystem
	}
}

// VKToPackage converts a resolve.VersionKey to an *extractor.Package
func VKToPackage(vk resolve.VersionKey) *extractor.Package {
	return &extractor.Package{
		Name:      vk.Name,
		Version:   vk.Version,
		Extractor: mockExtractor{},
		Metadata:  vk.System,
	}
}

// VKToPURL converts a resolve.VersionKey to a *purl.PackageURL
func VKToPURL(vk resolve.VersionKey) *purl.PackageURL {
	// This double-conversion is a bit hacky, but it prevents us from having to duplicate the logic in mockExtractor.ToPURL.
	pkg := VKToPackage(vk)
	return pkg.Extractor.ToPURL(pkg)
}

// mockExtractor is for VKToPackage to get the ecosystem.
type mockExtractor struct{}

// Ecosystem returns the ecosystem of the package.
func (e mockExtractor) Ecosystem(p *extractor.Package) string {
	return string(DepsDevToOSVEcosystem(p.Metadata.(resolve.System)))
}

// Unnecessary methods stubbed out.
func (e mockExtractor) Name() string                       { return "" }
func (e mockExtractor) Requirements() *plugin.Capabilities { return nil }
func (e mockExtractor) Version() int                       { return 0 }

// ToPURL converts a package created by this extractor into a PURL.
func (e mockExtractor) ToPURL(pkg *extractor.Package) *purl.PackageURL {
	switch e.Ecosystem(pkg) {
	case string(osvschema.EcosystemNPM):
		// The namespace is used for scoped packages, e.g. "@foo/bar"
		scope := ""
		name := pkg.Name
		if strings.HasPrefix(name, "@") {
			scope, name, _ = strings.Cut(name, "/")
		}
		return &purl.PackageURL{
			Type:      purl.TypeNPM,
			Namespace: scope,
			Name:      name,
			Version:   pkg.Version,
		}
	case string(osvschema.EcosystemMaven):
		group, artifact, _ := strings.Cut(pkg.Name, ":")
		return &purl.PackageURL{
			Type:      purl.TypeMaven,
			Namespace: group,
			Name:      artifact,
			Version:   pkg.Version,
		}
	case string(osvschema.EcosystemPyPI):
		return &purl.PackageURL{
			Type:    purl.TypePyPi,
			Name:    pkg.Name,
			Version: pkg.Version,
		}
	}
	return nil
}
