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

package dpkgsource_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/misc/dpkgsource"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"google.golang.org/protobuf/proto"
)

func TestAnnotate_DPKGSource(t *testing.T) {
	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	origFetchAptCachePolicy := dpkgsource.FetchAptCachePolicy
	defer func() { dpkgsource.FetchAptCachePolicy = origFetchAptCachePolicy }()

	mockPolicyResults := map[string]string{
		"libfoo": "http://deb.debian.org/debian",
		"libbar": "/var/lib/dpkg/status",
	}
	dpkgsource.FetchAptCachePolicy = mockGetAptCachePolicy(mockPolicyResults)

	annotatorInstance, err := dpkgsource.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name  string
		input *inventory.Inventory
		want  *inventory.Inventory
	}{
		{
			name: "debian_package_remote_source",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libfoo",
						Version:  "1.0",
						PURLType: purl.TypeDebian,
						Metadata: &dpkgmetadata.Metadata{},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libfoo",
						Version:  "1.0",
						PURLType: purl.TypeDebian,
						Metadata: &dpkgmetadata.Metadata{
							PackageSource: "http://deb.debian.org/debian",
						},
					},
				},
			},
		},
		{
			name: "debian_package_local_source",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeDebian,
						Metadata: &dpkgmetadata.Metadata{},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeDebian,
						Metadata: &dpkgmetadata.Metadata{
							PackageSource: "/var/lib/dpkg/status",
						},
					},
				},
			},
		},
		{
			name: "not_debian_package",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "not-deb",
						Version:  "1.0",
						PURLType: purl.TypeNPM,
						Metadata: &dpkgmetadata.Metadata{},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "not-deb",
						Version:  "1.0",
						PURLType: purl.TypeNPM,
						Metadata: &dpkgmetadata.Metadata{},
					},
				},
			},
		},
		{
			name: "debian_package_missing_source",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "missing-source",
						Version:  "1.0",
						PURLType: purl.TypeDebian,
						Metadata: &dpkgmetadata.Metadata{},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "missing-source",
						Version:  "1.0",
						PURLType: purl.TypeDebian,
						Metadata: &dpkgmetadata.Metadata{
							PackageSource: "unknown",
						},
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			inputPackagesCopy := make([]*extractor.Package, len(tt.input.Packages))
			for i, pkg := range tt.input.Packages {
				inputPackagesCopy[i] = copier.Copy(pkg).(*extractor.Package)
			}
			inv := &inventory.Inventory{Packages: inputPackagesCopy}

			err := annotatorInstance.Annotate(t.Context(), &annotator.ScanInput{}, inv)
			if err != nil {
				t.Fatalf("Annotate() unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.want, inv); diff != "" {
				t.Errorf("Annotate() unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapPackageToSource(t *testing.T) {
	tests := []struct {
		name           string
		aptCacheOutput string
		want           map[string]string
	}{
		{
			name:           "empty_input",
			aptCacheOutput: "",
			want:           map[string]string{},
		},
		{
			name: "single_package",
			aptCacheOutput: `mypackage:
  Installed: 20.1.1
  Candidate: 20.1.1
  Version table:
 *** 20.1.1
       500 http://deb.debian.org/debian stable/main amd64 Packages
`,
			want: map[string]string{"mypackage": "http://deb.debian.org/debian"},
		},
		{
			name: "multiple_packages",
			aptCacheOutput: `pkg1:
  Installed: 1.0
 *** 1.0 500
      500 http://deb.debian.org/debian stable/main amd64 Packages
pkg2:
  Installed: 2.1
 *** 2.1 900
      100 http://security.debian.org/debian-security stretch/updates/main amd64 Packages
`,
			want: map[string]string{
				"pkg1": "http://deb.debian.org/debian",
				"pkg2": "http://security.debian.org/debian-security",
			},
		},
		{
			name: "multiple_repositories",
			aptCacheOutput: `mypackage:
  Installed: 1.5
 *** 1.5 500
      500 http://deb.debian.org/debian stable/main amd64 Packages
      100 http://archive.debian.org/debian oldstable/main amd64 Packages
`,
			want: map[string]string{"mypackage": "http://deb.debian.org/debian"},
		},
		{
			name: "missing_installed_version",
			aptCacheOutput: `mypackage:
  Candidate: 1.0
  Version table:
     1.0 500
       500 http://deb.debian.org/debian stable/main amd64 Packages
`,
			want: map[string]string{},
		},
		{
			name: "whitespace_variation",
			aptCacheOutput: `mypackage:
  Installed: 20.1.1
  Candidate: 20.1.1
  Version table:
   *** 20.1.1
       500 http://deb.debian.org/debian stable/main amd64 Packages
`,
			want: map[string]string{"mypackage": "http://deb.debian.org/debian"},
		},
		{
			name: "package_name_special_chars",
			aptCacheOutput: `libfoo-dev:
  Installed: 1.0-1
      *** 1.0-1 500
      500 http://deb.debian.org/debian stable/main amd64 Packages
`,
			want: map[string]string{"libfoo-dev": "http://deb.debian.org/debian"},
		},
		{
			name: "input_ends_after_installed_version",
			aptCacheOutput: `mypackage:
  Installed: 1.0
      *** 1.0 500`,
			want: map[string]string{"mypackage": "unknown"},
		},
		{
			name: "repository_source_single_field",
			aptCacheOutput: `mypackage:
  Installed: 1.0
      *** 1.0 500
      onlyone`,
			want: map[string]string{"mypackage": "unknown"},
		},
		{
			name: "single_malformed_source",
			aptCacheOutput: `pkg1:
  Installed: 1.0
      *** 1.0 900
      malformedline

pkg2:
  Installed: 2.1
      *** 2.1 900
      500 http://deb.debian.org/debian stable/main amd64 Packages
      `,
			want: map[string]string{
				"pkg1": "unknown",
				"pkg2": "http://deb.debian.org/debian",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dpkgsource.MapPackageToSource(t.Context(), tt.aptCacheOutput)
			if err != nil {
				t.Fatalf("MapPackageToSource(%q) returned an unexpected error: %v", tt.aptCacheOutput, err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("MapPackageToSource(%q) returned an unexpected diff (-want +got):\n%s", tt.aptCacheOutput, diff)
			}
		})
	}
}

// Mock implementation for fetchAptCachePolicy
func mockGetAptCachePolicy(mockResults map[string]string) func(context.Context, []*extractor.Package) (map[string]string, error) {
	return func(ctx context.Context, pkgs []*extractor.Package) (map[string]string, error) {
		return mockResults, nil
	}
}
