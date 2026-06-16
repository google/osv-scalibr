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
