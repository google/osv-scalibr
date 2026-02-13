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

package brewsource_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/misc/brewsource"
	"github.com/google/osv-scalibr/extractor"
	metadata "github.com/google/osv-scalibr/extractor/filesystem/os/homebrew/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestAnnotate_brewsource(t *testing.T) {
	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	annotatorInstance, err := brewsource.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name  string
		input *inventory.Inventory
		want  *inventory.Inventory
	}{
		{
			name: "homebrew_package_notgit_metadata",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libfoo",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL: "https://some.other.url/libfoo/archive/refs/tags/v1.0.0.tar.gz",
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libfoo",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL: "https://some.other.url/libfoo/archive/refs/tags/v1.0.0.tar.gz",
						},
					},
				},
			},
		},
		{
			name: "homebrew_package_url_metadata",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL: "https://github.com/libbarowner/libbar/archive/refs/tags/v1.0.0.tar.gz",
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL: "https://github.com/libbarowner/libbar/archive/refs/tags/v1.0.0.tar.gz",
						},
						SourceCode: &extractor.SourceCodeIdentifier{
							Repo: "https://github.com/libbarowner/libbar",
						},
					},
				},
			},
		},
		{
			name: "homebrew_package_head_metadata",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL:  "https://some.other.url/libbar/archive/refs/tags/v1.0.0.tar.gz",
							Head: "https://github.com/libbarowner/libbar.git",
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL:  "https://some.other.url/libbar/archive/refs/tags/v1.0.0.tar.gz",
							Head: "https://github.com/libbarowner/libbar.git",
						},
						SourceCode: &extractor.SourceCodeIdentifier{
							Repo: "https://github.com/libbarowner/libbar.git",
						},
					},
				},
			},
		},
		{
			name: "homebrew_package_mirrors_metadata",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL:  "",
							Head: "https://some.other.url/libbarowner/libbar.git",
							Mirrors: []string{
								"https://mirror1.url/libbar/archive/refs/tags/v1.0.0.tar.gz",
								"https://gitlab.com/libbarowner/libbar/archive/refs/tags/v1.0.0.tar.gz",
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL:  "",
							Head: "https://some.other.url/libbarowner/libbar.git",
							Mirrors: []string{
								"https://mirror1.url/libbar/archive/refs/tags/v1.0.0.tar.gz",
								"https://gitlab.com/libbarowner/libbar/archive/refs/tags/v1.0.0.tar.gz",
							},
						},
						SourceCode: &extractor.SourceCodeIdentifier{
							Repo: "https://gitlab.com/libbarowner/libbar",
						},
					},
				},
			},
		},
		{
			name: "homebrew_package_all_metadata",
			input: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL:  "https://gitlab.com/libbarowner1/libbar/archive/refs/tags/v1.0.0.tar.gz",
							Head: "https://gitlab.com/libbarowner2/libbar.git",
							Mirrors: []string{
								"https://gitlab.com/libbarowner3/libbar/archive/refs/tags/v1.0.0.tar.gz",
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "libbar",
						Version:  "1.0",
						PURLType: purl.TypeBrew,
						Metadata: &metadata.Metadata{
							URL:  "https://gitlab.com/libbarowner1/libbar/archive/refs/tags/v1.0.0.tar.gz",
							Head: "https://gitlab.com/libbarowner2/libbar.git",
							Mirrors: []string{
								"https://gitlab.com/libbarowner3/libbar/archive/refs/tags/v1.0.0.tar.gz",
							},
						},
						SourceCode: &extractor.SourceCodeIdentifier{
							Repo: "https://gitlab.com/libbarowner1/libbar",
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
