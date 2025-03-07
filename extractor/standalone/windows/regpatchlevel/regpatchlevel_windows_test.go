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

//go:build windows

package regpatchlevel

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/testing/mockregistry"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name    string
		reg     *mockregistry.MockRegistry
		want    []*extractor.Inventory
		wantErr bool
	}{
		{
			name: "listOfPackages_returnsInventory",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					regPackagesRoot: &mockregistry.MockKey{
						KName: "Packages",
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3",
							},
						},
					},
					regPackagesRoot + "\\Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3": &mockregistry.MockKey{
						KName: "Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "CurrentState",
								VDataString: "112",
							},
							&mockregistry.MockValue{
								VName:       "Visibility",
								VDataString: "1",
							},
						},
					},
				},
			},
			want: []*extractor.Inventory{
				{
					Name:    "Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3",
					Version: "19041.2304.1.3",
				},
			},
		},
		{
			name: "packageNotVisible_returnsEmpty",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					regPackagesRoot: &mockregistry.MockKey{
						KName: "Packages",
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3",
							},
						},
					},
					regPackagesRoot + "\\Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3": &mockregistry.MockKey{
						KName: "Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "CurrentState",
								VDataString: "112",
							},
							&mockregistry.MockValue{
								VName:       "Visibility",
								VDataString: "0",
							},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "packageNotInstalled_returnsEmpty",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					regPackagesRoot: &mockregistry.MockKey{
						KName: "Packages",
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3",
							},
						},
					},
					regPackagesRoot + "\\Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3": &mockregistry.MockKey{
						KName: "Package_for_KB5020683~31bf3856ad364e35~amd64~~19041.2304.1.3",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "CurrentState",
								VDataString: "10",
							},
							&mockregistry.MockValue{
								VName:       "Visibility",
								VDataString: "1",
							},
						},
					},
				},
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Configuration{mockregistry.NewOpener(tc.reg)}
			e := New(cfg)
			got, err := e.Extract(t.Context(), nil)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Extract() returned an unexpected error: %v", err)
			}

			if tc.wantErr == true {
				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Extract() returned an unexpected diff (-want +got): %v", diff)
			}
		})
	}
}
