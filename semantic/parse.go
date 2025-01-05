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
		return mustParseAlpineVersion(str), nil
	case "ConanCenter":
		return mustParseSemverVersion(str), nil
	case "CRAN":
		return mustParseCRANVersion(str), nil
	case "crates.io":
		return mustParseSemverVersion(str), nil
	case "Debian":
		return mustParseDebianVersion(str), nil
	case "Go":
		return mustParseSemverVersion(str), nil
	case "Hex":
		return mustParseSemverVersion(str), nil
	case "Maven":
		return mustParseMavenVersion(str), nil
	case "npm":
		return mustParseSemverVersion(str), nil
	case "NuGet":
		return mustParseNuGetVersion(str), nil
	case "Packagist":
		return mustParsePackagistVersion(str), nil
	case "Pub":
		return mustParseSemverVersion(str), nil
	case "PyPI":
		return mustParsePyPIVersion(str), nil
	case "Red Hat":
		return mustParseRedHatVersion(str), nil
	case "RubyGems":
		return mustParseRubyGemsVersion(str), nil
	case "Ubuntu":
		return mustParseDebianVersion(str), nil
	}

	return nil, fmt.Errorf("%w %s", ErrUnsupportedEcosystem, ecosystem)
}
