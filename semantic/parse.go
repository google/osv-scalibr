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

// Package semantic provides version parsing and comparison for various ecosystems,
// matching the native versioning rules of each ecosystem.
package semantic

import (
	"errors"
	"fmt"
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
	// TODO(#457): support more ecosystems
	switch ecosystem {
	case "AlmaLinux":
		return parseRedHatVersion(str), nil
	case "Alpaquita":
		return parseAlpineVersion(str)
	case "Alpine":
		return parseAlpineVersion(str)
	case "Bitnami":
		return parseSemverVersion(str), nil
	case "Bioconductor":
		return parseSemverVersion(str), nil
	case "Chainguard":
		return parseAlpineVersion(str)
	case "ConanCenter":
		return parseSemverVersion(str), nil
	case "CRAN":
		return parseCRANVersion(str)
	case "crates.io":
		return parseSemverVersion(str), nil
	case "Debian":
		return parseDebianVersion(str)
	case "Go":
		return parseSemverVersion(str), nil
	case "Hackage":
		return parseHackageVersion(str)
	case "Hex":
		return parseSemverVersion(str), nil
	case "Mageia":
		return parseRedHatVersion(str), nil
	case "Maven":
		return parseMavenVersion(str), nil
	case "MinimOS":
		return parseAlpineVersion(str)
	case "npm":
		return parseSemverVersion(str), nil
	case "NuGet":
		return parseNuGetVersion(str), nil
	case "openEuler":
		return parseRedHatVersion(str), nil
	case "openSUSE":
		return parseRedHatVersion(str), nil
	case "Packagist":
		return parsePackagistVersion(str), nil
	case "Pub":
		return parseSemverVersion(str), nil
	case "PyPI":
		return parsePyPIVersion(str)
	case "Red Hat":
		return parseRedHatVersion(str), nil
	case "Rocky Linux":
		return parseRedHatVersion(str), nil
	case "RubyGems":
		return parseRubyGemsVersion(str), nil
	case "SUSE":
		return parseRedHatVersion(str), nil
	case "SwiftURL":
		return parseSemverVersion(str), nil
	case "Ubuntu":
		return parseDebianVersion(str)
	case "Wolfi":
		return parseAlpineVersion(str)
	}

	return nil, fmt.Errorf("%w %s", ErrUnsupportedEcosystem, ecosystem)
}
