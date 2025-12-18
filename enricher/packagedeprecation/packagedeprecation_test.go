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

package packagedeprecation_test

import (
	"testing"

	grpcpb "deps.dev/api/v3alpha"
	"github.com/google/go-cmp/cmp"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/packagedeprecation"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestEnrich(t *testing.T) {
	deprecationMap := map[packagedeprecation.VersionKey]bool{
		packagedeprecation.VersionKey{System: grpcpb.System_CARGO, Name: "url", Version: "2.5.3"}: true,
		packagedeprecation.VersionKey{System: grpcpb.System_CARGO, Name: "url", Version: "2.5.4"}: false,
	}

	fakeClient := newFakeClient(deprecationMap)
	e := mustNew(t, &fakeClient)

	tests := []struct {
		name    string
		client  packagedeprecation.Client
		inv     *inventory.Inventory
		want    *inventory.Inventory
		wantErr error
	}{
		{
			name: "empty_inventory",
			inv:  &inventory.Inventory{},
			want: &inventory.Inventory{},
		},
		{
			name: "unsupported_purl_type",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					&extractor.Package{
						PURLType: "invalid",
						Name:     "invalid",
						Version:  "invalid",
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					&extractor.Package{
						PURLType:   "invalid",
						Name:       "invalid",
						Version:    "invalid",
						Deprecated: false,
					},
				},
			},
		},
		{
			name: "package_version_not_found_in_depsdev",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					&extractor.Package{
						PURLType: purl.TypePyPi,
						Name:     "pip",
						Version:  "invalid",
					},
				}},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					&extractor.Package{
						PURLType:   purl.TypePyPi,
						Name:       "pip",
						Version:    "invalid",
						Deprecated: false,
					},
				},
			},
		},
		{
			name: "package_version_deprecated",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					&extractor.Package{
						PURLType: purl.TypeCargo,
						Name:     "url",
						Version:  "2.5.3",
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					&extractor.Package{
						PURLType:   purl.TypeCargo,
						Name:       "url",
						Version:    "2.5.3",
						Deprecated: true,
					},
				},
			},
		},
		{
			name: "package_version_not_deprecated",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					&extractor.Package{
						PURLType: purl.TypeCargo,
						Name:     "url",
						Version:  "2.5.4",
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					&extractor.Package{
						PURLType:   purl.TypeCargo,
						Name:       "url",
						Version:    "2.5.4",
						Deprecated: false,
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enrichErr := e.Enrich(t.Context(), nil, tc.inv)
			if enrichErr != nil {
				t.Errorf("Enrich() returned error %v, want %v", enrichErr, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, tc.inv); diff != "" {
				t.Errorf("Enrich() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func mustNew(t *testing.T, client packagedeprecation.Client) enricher.Enricher {
	t.Helper()
	e := packagedeprecation.New(&cpb.PluginConfig{}).(*packagedeprecation.Enricher)
	e.SetClient(client)
	return e
}
