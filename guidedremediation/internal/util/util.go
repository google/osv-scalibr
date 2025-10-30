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
	"deps.dev/util/resolve"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// DepsDevToOSVEcosystem converts a deps.dev resolve.System into an osvschema.Ecosystem.
// Unknown / invalid Systems become the empty ecosystem `osvschema.Ecosystem("")`.
func DepsDevToOSVEcosystem(sys resolve.System) osvconstants.Ecosystem {
	switch sys {
	case resolve.Maven:
		return osvconstants.EcosystemMaven
	case resolve.NPM:
		return osvconstants.EcosystemNPM
	case resolve.PyPI:
		return osvconstants.EcosystemPyPI
	case resolve.UnknownSystem:
		fallthrough
	default:
		return ""
	}
}

// OSVToDepsDevEcosystem converts an osvschema.Ecosystem into a deps.dev resolve.System.
// Unknown / invalid Ecosystems become `resolve.UnknownEcosystem`.
func OSVToDepsDevEcosystem(sys osvconstants.Ecosystem) resolve.System {
	switch sys {
	case osvconstants.EcosystemMaven:
		return resolve.Maven
	case osvconstants.EcosystemNPM:
		return resolve.NPM
	case osvconstants.EcosystemPyPI:
		return resolve.PyPI
	case
		osvconstants.EcosystemAlmaLinux,
		osvconstants.EcosystemAlpine,
		osvconstants.EcosystemAndroid,
		osvconstants.EcosystemBioconductor,
		osvconstants.EcosystemBitnami,
		osvconstants.EcosystemChainguard,
		osvconstants.EcosystemConanCenter,
		osvconstants.EcosystemCRAN,
		osvconstants.EcosystemCratesIO,
		osvconstants.EcosystemDebian,
		osvconstants.EcosystemGHC,
		osvconstants.EcosystemGitHubActions,
		osvconstants.EcosystemGo,
		osvconstants.EcosystemHackage,
		osvconstants.EcosystemHex,
		osvconstants.EcosystemKubernetes,
		osvconstants.EcosystemLinux,
		osvconstants.EcosystemMageia,
		osvconstants.EcosystemMinimOS,
		osvconstants.EcosystemNuGet,
		osvconstants.EcosystemOpenSUSE,
		osvconstants.EcosystemOSSFuzz,
		osvconstants.EcosystemPackagist,
		osvconstants.EcosystemPhotonOS,
		osvconstants.EcosystemPub,
		osvconstants.EcosystemRedHat,
		osvconstants.EcosystemRockyLinux,
		osvconstants.EcosystemRubyGems,
		osvconstants.EcosystemSUSE,
		osvconstants.EcosystemSwiftURL,
		osvconstants.EcosystemUbuntu,
		osvconstants.EcosystemWolfi:
		fallthrough
	default:
		return resolve.UnknownSystem
	}
}
