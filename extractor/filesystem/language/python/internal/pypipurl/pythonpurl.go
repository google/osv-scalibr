// Package pypipurl converts an inventory to a PyPI type PackageURL.
package pypipurl

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/cachedregexp"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL following the purl PyPI spec:
// - Name is lowercased
// - Replaces all runs of ` _ , - ` with -
//
// See: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#pypi
// And: https://peps.python.org/pep-0503/#normalized-names
//
// This function does *not* handle package names with invalid characters, and will
// return them as is.
func MakePackageURL(i *extractor.Inventory) *purl.PackageURL {
	specialCharRunFinder := cachedregexp.MustCompile("[-_.]+")
	normalizedName := specialCharRunFinder.ReplaceAllLiteralString(strings.ToLower(i.Name), "-")
	return &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    normalizedName,
		Version: i.Version,
	}
}
