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

package purl_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	gopurl "github.com/google/osv-scalibr/extractor/filesystem/language/golang/purl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURL(t *testing.T) {
	tests := []struct {
		desc    string
		name    string
		version string
		want    *purl.PackageURL
	}{
		{
			desc:    "split_name_namespace",
			name:    "github.com/google/osv-scalibr",
			version: "1.2.3",
			want: &purl.PackageURL{
				Type:      purl.TypeGolang,
				Name:      "osv-scalibr",
				Namespace: "github.com/google",
				Version:   "1.2.3",
			},
		},
		{
			desc:    "mixed_case_name_namespace",
			name:    "github.com/Microsoft/Go-Rustaudit",
			version: "1.2.3",
			want: &purl.PackageURL{
				Type:      purl.TypeGolang,
				Name:      "go-rustaudit",
				Namespace: "github.com/microsoft",
				Version:   "1.2.3",
			},
		},
		{
			desc:    "no_namespace",
			name:    "name",
			version: "1.2.3",
			want: &purl.PackageURL{
				Type:    purl.TypeGolang,
				Name:    "name",
				Version: "1.2.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := gopurl.MakePackageURL(tt.name, tt.version)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("MakePackageURL() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
