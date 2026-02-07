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

// Package pypipurl converts a package to a PyPI type PackageURL.
package pypipurl_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pypipurl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    *purl.PackageURL
	}{
		{
			name:    "test",
			version: "1.0.0",
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test",
				Version: "1.0.0",
			},
		},
		{
			name:    "test-with-dashes",
			version: "1.0.0",
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-dashes",
				Version: "1.0.0",
			},
		},
		{
			name:    "test_with_underscore",
			version: "1.0.0",
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-underscore",
				Version: "1.0.0",
			},
		},
		{
			name:    "test___with_long__underscore",
			version: "1.0.0",
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-long-underscore",
				Version: "1.0.0",
			},
		},
		{
			name:    "test.with-mixed_symbols",
			version: "1.0.0",
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-mixed-symbols",
				Version: "1.0.0",
			},
		},
		{
			name:    "test.__-with_mixed_.--run",
			version: "1.0.0",
			want: &purl.PackageURL{
				Type:    "pypi",
				Name:    "test-with-mixed-run",
				Version: "1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pypipurl.MakePackageURL(tt.name, tt.version)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("MakePackageURL() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
