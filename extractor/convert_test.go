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

package extractor_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
)

func TestToPURL(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want *purl.PackageURL
	}{
		{
			name: "no_purl_type",
			pkg: &extractor.Package{
				Name:    "name",
				Version: "version",
			},
			want: nil,
		},
		{
			name: "simple_purl",
			pkg: &extractor.Package{
				Name:     "name",
				Version:  "version",
				PURLType: purl.TypeGolang,
			},
			want: &purl.PackageURL{
				Type:    purl.TypeGolang,
				Name:    "name",
				Version: "version",
			},
		},
		{
			name: "python_purl",
			pkg: &extractor.Package{
				Name:      "Name",
				Version:   "1.2.3",
				PURLType:  purl.TypePyPi,
				Locations: []string{"location"},
			},
			want: &purl.PackageURL{
				Type:    purl.TypePyPi,
				Name:    "name",
				Version: "1.2.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkg.PURL()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("%v.PURL(): unexpected PURL (-want +got):\n%s", tt.pkg, diff)
			}
		})
	}
}
