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

package regosversion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
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
			name: "newerKnownWindows_returnsFullVersion",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					regVersionPath: &mockregistry.MockKey{
						KName: "CurrentVersion",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "CurrentMajorVersionNumber",
								VDataString: "10",
							},
							&mockregistry.MockValue{
								VName:       "CurrentMinorVersionNumber",
								VDataString: "0",
							},
							&mockregistry.MockValue{
								VName:       "CurrentBuildNumber",
								VDataString: "22000",
							},
							&mockregistry.MockValue{
								VName:       "UBR",
								VDataString: "1234",
							},
							&mockregistry.MockValue{
								VName:       "InstallationType",
								VDataString: "client",
							},
						},
					},
				},
			},
			want: []*extractor.Inventory{
				{
					Name:    "windows_11:21H2",
					Version: "10.0.22000.1234",
					Metadata: metadata.OSVersion{
						Product:     "windows_11:21H2",
						FullVersion: "10.0.22000.1234",
					},
				},
			},
		},
		{
			name: "newerUnknownWindows_returnsFullVersion",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					regVersionPath: &mockregistry.MockKey{
						KName: "CurrentVersion",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "CurrentMajorVersionNumber",
								VDataString: "10",
							},
							&mockregistry.MockValue{
								VName:       "CurrentMinorVersionNumber",
								VDataString: "0",
							},
							&mockregistry.MockValue{
								VName:       "CurrentBuildNumber",
								VDataString: "12345",
							},
							&mockregistry.MockValue{
								VName:       "UBR",
								VDataString: "1234",
							},
							&mockregistry.MockValue{
								VName:       "InstallationType",
								VDataString: "client",
							},
						},
					},
				},
			},
			want: []*extractor.Inventory{
				{
					Name:    "unknownWindows",
					Version: "10.0.12345.1234",
					Metadata: metadata.OSVersion{
						Product:     "unknownWindows",
						FullVersion: "10.0.12345.1234",
					},
				},
			},
		},
		{
			name: "olderKnownWindows_returnsFullVersion",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					regVersionPath: &mockregistry.MockKey{
						KName: "CurrentVersion",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "CurrentVersion",
								VDataString: "5.1",
							},
							&mockregistry.MockValue{
								VName:       "CurrentBuildNumber",
								VDataString: "2600",
							},
							&mockregistry.MockValue{
								VName:       "BuildLabEx",
								VDataString: "5678.1234",
							},
							&mockregistry.MockValue{
								VName:       "InstallationType",
								VDataString: "client",
							},
						},
					},
				},
			},
			want: []*extractor.Inventory{
				{
					Name:    "windows_xp",
					Version: "5.1.2600.1234",
					Metadata: metadata.OSVersion{
						Product:     "windows_xp",
						FullVersion: "5.1.2600.1234",
					},
				},
			},
		},
		{
			name: "olderUnknownWindows_returnsFullVersion",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					regVersionPath: &mockregistry.MockKey{
						KName: "CurrentVersion",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "CurrentVersion",
								VDataString: "5.1",
							},
							&mockregistry.MockValue{
								VName:       "CurrentBuildNumber",
								VDataString: "1234",
							},
							&mockregistry.MockValue{
								VName:       "BuildLabEx",
								VDataString: "5678.1234",
							},
							&mockregistry.MockValue{
								VName:       "InstallationType",
								VDataString: "client",
							},
						},
					},
				},
			},
			want: []*extractor.Inventory{
				{
					Name:    "unknownWindows",
					Version: "5.1.1234.1234",
					Metadata: metadata.OSVersion{
						Product:     "unknownWindows",
						FullVersion: "5.1.1234.1234",
					},
				},
			},
		},
		{
			name:    "emptyRegistry_returnsError",
			reg:     &mockregistry.MockRegistry{},
			wantErr: true,
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
