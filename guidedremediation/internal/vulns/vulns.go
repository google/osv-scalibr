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

// Package vulns implements local matching for OSV records.
package vulns

import (
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/guidedremediation/internal/util"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// VKToPackage converts a resolve.VersionKey to an *extractor.Package
func VKToPackage(vk resolve.VersionKey) *extractor.Package {
	p := &extractor.Package{
		Name:      vk.Name,
		Version:   vk.Version,
		Extractor: mockExtractor{},
		Metadata:  vk.System,
	}
	purl := mockExtractor{}.ToPURL(p)
	if purl != nil {
		p.PURLType = purl.Type
	}
	return p
}

// mockExtractor is for VKToPackage to get the ecosystem.
type mockExtractor struct{}

// Ecosystem returns the ecosystem of the package.
func (e mockExtractor) Ecosystem(p *extractor.Package) string {
	return string(util.DepsDevToOSVEcosystem(p.Metadata.(resolve.System)))
}

// Unnecessary methods stubbed out.
func (e mockExtractor) Name() string                       { return "" }
func (e mockExtractor) Requirements() *plugin.Capabilities { return nil }
func (e mockExtractor) Version() int                       { return 0 }

// ToPURL converts a package created by this extractor into a PURL.
func (e mockExtractor) ToPURL(pkg *extractor.Package) *purl.PackageURL {
	switch e.Ecosystem(pkg) {
	case string(osvschema.EcosystemNPM):
		return &purl.PackageURL{
			Type:    purl.TypeNPM,
			Name:    pkg.Name,
			Version: pkg.Version,
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

// IsAffected returns true if the Vulnerability applies to the package version of the Package.
func IsAffected(vuln *osvschema.Vulnerability, pkg *extractor.Package) bool {
	resolveSys := util.OSVToDepsDevEcosystem(osvschema.Ecosystem(pkg.Ecosystem()))
	if resolveSys == resolve.UnknownSystem {
		return false
	}
	sys := resolveSys.Semver()
	for _, affected := range vuln.Affected {
		if affected.Package.Ecosystem != pkg.Ecosystem() ||
			affected.Package.Name != pkg.Name {
			continue
		}
		if slices.Contains(affected.Versions, pkg.Version) {
			return true
		}
		for _, r := range affected.Ranges {
			if r.Type != "ECOSYSTEM" &&
				!(r.Type == "SEMVER" && affected.Package.Ecosystem == "npm") {
				continue
			}
			events := slices.Clone(r.Events)
			eventVersion := func(e osvschema.Event) string {
				if e.Introduced != "" {
					return e.Introduced
				}
				if e.Fixed != "" {
					return e.Fixed
				}
				return e.LastAffected
			}
			slices.SortFunc(events, func(a, b osvschema.Event) int {
				aVer := eventVersion(a)
				bVer := eventVersion(b)
				if aVer == "0" {
					if bVer == "0" {
						return 0
					}
					return -1
				}
				if bVer == "0" {
					return 1
				}
				// sys.Compare on strings is expensive, should consider precomputing sys.Parse
				return sys.Compare(aVer, bVer)
			})
			idx, exact := slices.BinarySearchFunc(events, pkg.Version, func(e osvschema.Event, v string) int {
				eVer := eventVersion(e)
				if eVer == "0" {
					return -1
				}
				return sys.Compare(eVer, v)
			})
			if exact {
				e := events[idx]
				// Version is exactly on a range-inclusive event
				if e.Introduced != "" || e.LastAffected != "" {
					return true
				}
				// Version is between events, only match if previous event is Introduced
			} else if idx != 0 && events[idx-1].Introduced != "" {
				return true
			}
		}
	}
	return false
}
