// Package pypipurl converts an inventory to a PyPI type PackageURL.
package pypipurl_test

import (
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/internal/pypipurl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURL(t *testing.T) {
	tests := []struct {
		name string
		arg  extractor.Inventory
		want *purl.PackageURL
	}{
		{
			arg: extractor.Inventory{
				Name:    "test",
				Version: "1.0.0",
			},
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test",
				Version: "1.0.0",
			},
		},
		{
			arg: extractor.Inventory{
				Name:    "test-with-dashes",
				Version: "1.0.0",
			},
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-dashes",
				Version: "1.0.0",
			},
		},
		{
			arg: extractor.Inventory{
				Name:    "test_with_underscore",
				Version: "1.0.0",
			},
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-underscore",
				Version: "1.0.0",
			},
		},
		{
			arg: extractor.Inventory{
				Name:    "test___with_long__underscore",
				Version: "1.0.0",
			},
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-long-underscore",
				Version: "1.0.0",
			},
		},
		{
			arg: extractor.Inventory{
				Name:    "test.with-mixed_symbols",
				Version: "1.0.0",
			},
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-mixed-symbols",
				Version: "1.0.0",
			},
		},
		{
			arg: extractor.Inventory{
				Name:    "test.__-with_mixed_.--run",
				Version: "1.0.0",
			},
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-mixed-run",
				Version: "1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pypipurl.MakePackageURL(&tt.arg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MakePackageURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
