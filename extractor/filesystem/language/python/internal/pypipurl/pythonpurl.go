// Package pypipurl converts an inventory to a PyPI type PackageURL.
package pypipurl

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL following the purl PyPI spec:
// - Name is lowercased
// - Replaces _ with -
//
// See: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#pypi
func MakePackageURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    strings.ReplaceAll(strings.ToLower(i.Name), "_", "-"),
		Version: i.Version,
	}
}
