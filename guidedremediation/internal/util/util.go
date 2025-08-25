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
	case
		osvschema.EcosystemAlmaLinux,
		osvschema.EcosystemAlpine,
		osvschema.EcosystemAndroid,
		osvschema.EcosystemBioconductor,
		osvschema.EcosystemBitnami,
		osvschema.EcosystemChainguard,
		osvschema.EcosystemConanCenter,
		osvschema.EcosystemCRAN,
		osvschema.EcosystemCratesIO,
		osvschema.EcosystemDebian,
		osvschema.EcosystemGHC,
		osvschema.EcosystemGitHubActions,
		osvschema.EcosystemGo,
		osvschema.EcosystemHackage,
		osvschema.EcosystemHex,
		osvschema.EcosystemKubernetes,
		osvschema.EcosystemLinux,
		osvschema.EcosystemMageia,
		osvschema.EcosystemMinimOS,
		osvschema.EcosystemNuGet,
		osvschema.EcosystemOpenSUSE,
		osvschema.EcosystemOSSFuzz,
		osvschema.EcosystemPackagist,
		osvschema.EcosystemPhotonOS,
		osvschema.EcosystemPub,
		osvschema.EcosystemRedHat,
		osvschema.EcosystemRockyLinux,
		osvschema.EcosystemRubyGems,
		osvschema.EcosystemSUSE,
		osvschema.EcosystemSwiftURL,
		osvschema.EcosystemUbuntu,
		osvschema.EcosystemWolfi:
		fallthrough
	default:
		return resolve.UnknownSystem
	}
}
