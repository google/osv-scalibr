// Package semantic provides version parsing and comparison for various ecosystems,
// matching the native versioning rules of each ecosystem.
package semantic

import (
	"errors"
	"fmt"
)

var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem")
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
	//nolint:exhaustive // Using strings to specify ecosystem instead of lockfile types
	switch ecosystem {
	case "Alpine":
		return parseAlpineVersion(str)
	case "ConanCenter":
		return parseSemverVersion(str)
	case "CRAN":
		return parseCRANVersion(str)
	case "crates.io":
		return parseSemverVersion(str)
	case "Debian":
		return parseDebianVersion(str)
	case "Go":
		return parseSemverVersion(str)
	case "Hex":
		return parseSemverVersion(str)
	case "Maven":
		return parseMavenVersion(str)
	case "npm":
		return parseSemverVersion(str)
	case "NuGet":
		return parseNuGetVersion(str)
	case "Packagist":
		return parsePackagistVersion(str)
	case "Pub":
		return parseSemverVersion(str)
	case "PyPI":
		return parsePyPIVersion(str)
	case "Red Hat":
		return parseRedHatVersion(str)
	case "RubyGems":
		return parseRubyGemsVersion(str)
	case "Ubuntu":
		return parseDebianVersion(str)
	}

	return nil, fmt.Errorf("%w %s", ErrUnsupportedEcosystem, ecosystem)
}
