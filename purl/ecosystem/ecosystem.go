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

// Package ecosystem provides utilities to convert PURLs to OSV ecosystems.
package ecosystem

import (
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// FromPURL converts a PURL to an OSV Ecosystem.
func FromPURL(p *purl.PackageURL) osvecosystem.Parsed {
	if p == nil {
		return osvecosystem.Parsed{}
	}

	if p.Type == purl.TypeApk {
		return apkToEcosystem(p)
	}
	if p.Type == purl.TypeDebian {
		return debToEcosystem(p)
	}

	return osvecosystem.Parsed{}
}

func apkToEcosystem(p *purl.PackageURL) osvecosystem.Parsed {
	ecosystem := osvconstants.EcosystemAlpine
	if p.Namespace == "wolfi" {
		return osvecosystem.FromEcosystem(osvconstants.EcosystemWolfi)
	}
	if p.Namespace == "chainguard" {
		return osvecosystem.FromEcosystem(osvconstants.EcosystemChainguard)
	}

	distro := ""
	for _, q := range p.Qualifiers {
		if q.Key == "distro" {
			distro = q.Value
			break
		}
	}

	if distro != "" {
		versionID := distro
		if idx := strings.LastIndex(distro, "-"); idx != -1 {
			versionID = distro[idx+1:]
		}
		versionID = strings.TrimLeft(versionID, "vV")

		if versionID == "edge" {
			return osvecosystem.Parsed{Ecosystem: osvconstants.EcosystemAlpine, Suffix: "edge"}
		}

		if len(versionID) > 0 && versionID[0] >= '0' && versionID[0] <= '9' {
			parts := strings.Split(versionID, ".")
			if len(parts) >= 2 {
				return osvecosystem.Parsed{Ecosystem: osvconstants.EcosystemAlpine, Suffix: fmt.Sprintf("v%s.%s", parts[0], parts[1])}
			}
		}
	}

	return osvecosystem.FromEcosystem(ecosystem)
}

func debToEcosystem(p *purl.PackageURL) osvecosystem.Parsed {
	distro := ""
	for _, q := range p.Qualifiers {
		if q.Key == "distro" {
			distro = q.Value
			break
		}
	}

	// Determine base ecosystem
	var baseEcosystem osvconstants.Ecosystem
	namespace := strings.ToLower(p.Namespace)

	if namespace == "debian" {
		baseEcosystem = osvconstants.EcosystemDebian
	} else if namespace == "ubuntu" {
		baseEcosystem = osvconstants.EcosystemUbuntu
	} else if distro != "" {
		// Fallback: try to guess from distro qualifier
		distroLower := strings.ToLower(distro)
		if strings.HasPrefix(distroLower, "debian") {
			baseEcosystem = osvconstants.EcosystemDebian
		} else if strings.HasPrefix(distroLower, "ubuntu") {
			baseEcosystem = osvconstants.EcosystemUbuntu
		}
	}

	if baseEcosystem == "" {
		return osvecosystem.Parsed{}
	}

	if distro == "" {
		return osvecosystem.FromEcosystem(baseEcosystem)
	}

	idx := strings.LastIndex(distro, "-")
	version := distro[idx+1:]

	if mapped := mapDistro(baseEcosystem, version); mapped != "" {
		version = mapped
	}

	return osvecosystem.Parsed{Ecosystem: baseEcosystem, Suffix: version}
}

func mapDistro(ecosystem osvconstants.Ecosystem, distro string) string {
	switch ecosystem {
	case osvconstants.EcosystemDebian:
		return debianDistroToSuffix[strings.ToLower(distro)]
	case osvconstants.EcosystemUbuntu:
		return ubuntuDistroToSuffix[strings.ToLower(distro)]
	}
	return ""
}

var debianDistroToSuffix = map[string]string{
	"buzz":     "1.1",
	"rex":      "1.2",
	"bo":       "1.3",
	"hamm":     "2",
	"slink":    "2.1",
	"potato":   "2.2",
	"woody":    "3",
	"sarge":    "3.1",
	"etch":     "4",
	"lenny":    "5",
	"squeeze":  "6",
	"wheezy":   "7",
	"jessie":   "8",
	"stretch":  "9",
	"buster":   "10",
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
	"forky":    "14",
	"duke":     "15",
}

var ubuntuDistroToSuffix = map[string]string{
	"precise":  "12.04:LTS",
	"12.04":    "12.04:LTS",
	"quantal":  "12.10",
	"raring":   "13.04",
	"trusty":   "14.04:LTS",
	"14.04":    "14.04:LTS",
	"utopic":   "14.10",
	"vivid":    "15.04",
	"wily":     "15.10",
	"xenial":   "16.04:LTS",
	"16.04":    "16.04:LTS",
	"yakkety":  "16.10",
	"zesty":    "17.04",
	"artful":   "17.10",
	"bionic":   "18.04:LTS",
	"18.04":    "18.04:LTS",
	"cosmic":   "18.10",
	"disco":    "19.04",
	"eoan":     "19.10",
	"focal":    "20.04:LTS",
	"20.04":    "20.04:LTS",
	"groovy":   "20.10",
	"hirsute":  "21.04",
	"impish":   "21.10",
	"jammy":    "22.04:LTS",
	"22.04":    "22.04:LTS",
	"kinetic":  "22.10",
	"lunar":    "23.04",
	"mantic":   "23.10",
	"noble":    "24.04:LTS",
	"24.04":    "24.04:LTS",
	"oracular": "24.10",
	"plucky":   "25.04",
	"questing": "25.10",
	"resolute": "26.04:LTS",
	"26.04":    "26.04:LTS",
}
