package pkgmatcher

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
)

// form returns the singular or plural form that should be used based on the given count
func form(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}

	return plural
}

func packageToString(pkg *extractor.Inventory) string {
	source := pkg.SourceCode
	commit := "<no commit>"
	if source != nil && source.Commit != "" {
		commit = source.Commit
	}

	groups := "<no groups>"
	if dg, ok := pkg.Metadata.(osv.DepGroups); ok {
		if depGroups := dg.DepGroups(); len(depGroups) != 0 {
			groups = strings.Join(dg.DepGroups(), "/")
		}
	}

	locations := strings.Join(pkg.Locations, ", ")

	return fmt.Sprintf("%s@%s (%s, %s) @ [%s]", pkg.Name, pkg.Version, commit, groups, locations)
}

func hasPackage(t *testing.T, packages []*extractor.Inventory, pkg *extractor.Inventory) bool {
	t.Helper()

	for _, details := range packages {
		// _test := cmp.Diff(details, pkg)
		// println(_test)
		if cmp.Equal(details, pkg) {
			return true
		}
	}

	return false
}

func findMissingPackages(t *testing.T, actualPackages []*extractor.Inventory, expectedPackages []*extractor.Inventory) []*extractor.Inventory {
	t.Helper()
	var missingPackages []*extractor.Inventory

	for _, pkg := range actualPackages {
		if !hasPackage(t, expectedPackages, pkg) {
			missingPackages = append(missingPackages, pkg)
		}
	}

	return missingPackages
}

func ExpectPackages(t *testing.T, actualInventories []*extractor.Inventory, expectedInventories []*extractor.Inventory) {
	t.Helper()

	if len(expectedInventories) != len(actualInventories) {
		t.Errorf(
			"Expected to get %d %s, but got %d",
			len(expectedInventories),
			form(len(expectedInventories), "package", "packages"),
			len(actualInventories),
		)
	}

	missingActualPackages := findMissingPackages(t, actualInventories, expectedInventories)
	missingExpectedPackages := findMissingPackages(t, expectedInventories, actualInventories)

	if len(missingActualPackages) != 0 {
		for _, unexpectedPackage := range missingActualPackages {
			t.Errorf("Did not expect %s", packageToString(unexpectedPackage))
		}
	}

	if len(missingExpectedPackages) != 0 {
		for _, unexpectedPackage := range missingExpectedPackages {
			t.Errorf("Did not find   %s", packageToString(unexpectedPackage))
		}
	}
}
