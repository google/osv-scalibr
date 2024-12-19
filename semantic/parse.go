// Package semantic provides version parsing and comparison for various ecosystems,
// matching the native versioning rules of each ecosystem.
package semantic

import (
	"errors"
	"fmt"
)

var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem")

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
		return parseAlpineVersion(str), nil
	case "ConanCenter":
		return parseSemverVersion(str), nil
	case "CRAN":
		return parseCRANVersion(str), nil
	case "crates.io":
		return parseSemverVersion(str), nil
	case "Debian":
		return parseDebianVersion(str), nil
	case "Go":
		return parseSemverVersion(str), nil
	case "Hex":
		return parseSemverVersion(str), nil
	case "Maven":
		return parseMavenVersion(str), nil
	case "npm":
		return parseSemverVersion(str), nil
	case "NuGet":
		return parseNuGetVersion(str), nil
	case "Packagist":
		return parsePackagistVersion(str), nil
	case "Pub":
		return parseSemverVersion(str), nil
	case "PyPI":
		return parsePyPIVersion(str), nil
	case "Red Hat":
		return parseRedHatVersion(str), nil
	case "RubyGems":
		return parseRubyGemsVersion(str), nil
	case "Ubuntu":
		return parseDebianVersion(str), nil
	}

	return nil, fmt.Errorf("%w %s", ErrUnsupportedEcosystem, ecosystem)
}
