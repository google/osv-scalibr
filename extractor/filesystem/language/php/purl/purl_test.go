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

package purl_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	composerpurl "github.com/google/osv-scalibr/extractor/filesystem/language/php/purl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURL(t *testing.T) {
	tests := []struct {
		desc    string
		name    string
		version string
		want    *purl.PackageURL
		wantStr string
	}{
		{
			desc:    "split_name_namespace",
			name:    "symfony/http-kernel",
			version: "8.1.0",
			want: &purl.PackageURL{
				Type:      purl.TypeComposer,
				Namespace: "symfony",
				Name:      "http-kernel",
				Version:   "8.1.0",
			},
			wantStr: "pkg:composer/symfony/http-kernel@8.1.0",
		},
		{
			desc:    "mixed_case_name_namespace",
			name:    "Symfony/HTTP-Kernel",
			version: "8.1.0",
			want: &purl.PackageURL{
				Type:      purl.TypeComposer,
				Namespace: "symfony",
				Name:      "http-kernel",
				Version:   "8.1.0",
			},
			wantStr: "pkg:composer/symfony/http-kernel@8.1.0",
		},
		{
			desc:    "no_namespace",
			name:    "name",
			version: "1.2.3",
			want: &purl.PackageURL{
				Type:    purl.TypeComposer,
				Name:    "name",
				Version: "1.2.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := composerpurl.MakePackageURL(tt.name, tt.version)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("composerpurl.MakePackageURL(%v, %v): unexpected PURL (-want +got):\n%s", tt.name, tt.version, diff)
			}
			if tt.wantStr != "" && got.String() != tt.wantStr {
				t.Errorf("composerpurl.MakePackageURL(%v, %v).String() = %q, want %q", tt.name, tt.version, got.String(), tt.wantStr)
			}
		})
	}
}
