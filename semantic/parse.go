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

// Package semantic provides version parsing and comparison for various ecosystems,
// matching the native versioning rules of each ecosystem.
package semantic

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedEcosystem is returned for unsupported ecosystems.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem")

// ErrInvalidVersion is returned for malformed version strings.
var ErrInvalidVersion = errors.New("invalid version")

// MustParse is like Parse but panics if the ecosystem is not supported.
func MustParse(str string, ecosystem string) Version {
	v, err := Parse(str, ecosystem)

	if err != nil {
		panic(err)
	}

	return v
}

// Parse attempts to parse the given string as a version for the specified ecosystem,
// returning an ErrUnsupportedEcosystem error if the ecosystem is not supported.
func Parse(str string, ecosystem string) (Version, error) {
	// Remove the version suffix from the ecosystem name.
	parts := strings.Split(ecosystem, ":")
	if len(parts) > 1 {
		ecosystem = parts[0]
	}

	// TODO(#457): support more ecosystems
	switch ecosystem {
	case "AlmaLinux":
		return ParseRedHatVersion(str), nil
	case "Alpaquita":
		return ParseAlpineVersion(str)
	case "Alpine":
		return ParseAlpineVersion(str)
	case "BellSoft Hardened Containers":
		return ParseAlpineVersion(str)
	case "Bitnami":
		return ParseSemverVersion(str), nil
	case "Bioconductor":
		return ParseSemverVersion(str), nil
	case "Chainguard":
		return ParseAlpineVersion(str)
	case "ConanCenter":
		return ParseSemverVersion(str), nil
	case "CRAN":
		return ParseCRANVersion(str)
	case "crates.io":
		return ParseSemverVersion(str), nil
	case "Debian":
		return ParseDebianVersion(str)
	case "GHC":
		return ParseSemverVersion(str), nil
	case "Go":
		return ParseSemverVersion(str), nil
	case "Hackage":
		return ParseHackageVersion(str)
	case "Hex":
		return ParseSemverVersion(str), nil
	case "Julia":
		return ParseSemverVersion(str), nil
	case "Mageia":
		return ParseRedHatVersion(str), nil
	case "Maven":
		return ParseMavenVersion(str), nil
	case "MinimOS":
		return ParseAlpineVersion(str)
	case "npm":
		return ParseSemverVersion(str), nil
	case "NuGet":
		return ParseNuGetVersion(str), nil
	case "openEuler":
		return ParseRedHatVersion(str), nil
	case "openSUSE":
		return ParseRedHatVersion(str), nil
	case "Packagist":
		return ParsePackagistVersion(str), nil
	case "Pub":
		return ParsePubVersion(str), nil
	case "PyPI":
		return ParsePyPIVersion(str)
	case "Red Hat":
		return ParseRedHatVersion(str), nil
	case "Rocky Linux":
		return ParseRedHatVersion(str), nil
	case "RubyGems":
		return ParseRubyGemsVersion(str), nil
	case "SUSE":
		return ParseRedHatVersion(str), nil
	case "SwiftURL":
		return ParseSemverVersion(str), nil
	case "Ubuntu":
		return ParseDebianVersion(str)
	case "Wolfi":
		return ParseAlpineVersion(str)
	}

	return nil, fmt.Errorf("%w %s", ErrUnsupportedEcosystem, ecosystem)
}
