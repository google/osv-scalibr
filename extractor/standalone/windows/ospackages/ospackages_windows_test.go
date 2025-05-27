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

package ospackages

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/mockregistry"
)

func TestExtract(t *testing.T) {
	hkuRootWithTwoUsers := &mockregistry.MockKey{
		KName: "",
		KSubkeys: []registry.Key{
			&mockregistry.MockKey{KName: "User00"},
			&mockregistry.MockKey{KName: "User01"},
		},
	}

	tests := []struct {
		name    string
		reg     *mockregistry.MockRegistry
		want    []*extractor.Package
		wantErr bool
	}{
		{
			name: "reports_system_software_and_wow64",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					// User-related installs.
					"":                                     hkuRootWithTwoUsers,
					"User00\\" + regUninstallRelativeUsers: &mockregistry.MockKey{},
					// System-related installs.
					regUninstallRootDefault: &mockregistry.MockKey{
						KName: "Uninstall",
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "SomeSoftware",
								KValues: []registry.Value{
									&mockregistry.MockValue{VName: "DisplayName"},
									&mockregistry.MockValue{VName: "DisplayVersion"},
								},
							},
						},
					},
					regUninstallRootDefault + "\\SomeSoftware": &mockregistry.MockKey{
						KName: "SomeSoftware",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "DisplayName",
								VDataString: "Some software install",
							},
							&mockregistry.MockValue{
								VName:       "DisplayVersion",
								VDataString: "1.0.0",
							},
						},
					},
					regUninstallRootWow64: &mockregistry.MockKey{
						KName: "Uninstall",
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "SomeSoftwareWow64",
								KValues: []registry.Value{
									&mockregistry.MockValue{VName: "DisplayName"},
									&mockregistry.MockValue{VName: "DisplayVersion"},
								},
							},
						},
					},
					regUninstallRootWow64 + "\\SomeSoftwareWow64": &mockregistry.MockKey{
						KName: "SomeSoftwareWow64",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "DisplayName",
								VDataString: "Some software install wow64",
							},
							&mockregistry.MockValue{
								VName:       "DisplayVersion",
								VDataString: "1.4.0",
							},
						},
					},
				},
			},
			want: []*extractor.Package{
				{Name: "Some software install", Version: "1.0.0", PURLType: "windows"},
				{Name: "Some software install wow64", Version: "1.4.0", PURLType: "windows"},
			},
		},
		{
			name: "reports_user_software",
			reg: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					// User-related installs.
					"": hkuRootWithTwoUsers,
					"User00\\" + regUninstallRelativeUsers: &mockregistry.MockKey{
						KName: "Uninstall",
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "SomeSoftwareUser00",
								KValues: []registry.Value{
									&mockregistry.MockValue{VName: "DisplayName"},
									&mockregistry.MockValue{VName: "DisplayVersion"},
								},
							},
						},
					},
					"User00\\" + regUninstallRelativeUsers + "\\SomeSoftwareUser00": &mockregistry.MockKey{
						KName: "SomeSoftwareForUser00",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "DisplayName",
								VDataString: "Some software install for user00",
							},
							&mockregistry.MockValue{
								VName:       "DisplayVersion",
								VDataString: "1.00.1",
							},
						},
					},
					"User01\\" + regUninstallRelativeUsers: &mockregistry.MockKey{
						KName: "Uninstall",
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "SomeSoftwareUser01",
								KValues: []registry.Value{
									&mockregistry.MockValue{VName: "DisplayName"},
									&mockregistry.MockValue{VName: "DisplayVersion"},
								},
							},
						},
					},
					"User01\\" + regUninstallRelativeUsers + "\\SomeSoftwareUser01": &mockregistry.MockKey{
						KName: "SomeSoftwareForUser01",
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName:       "DisplayName",
								VDataString: "GooGet - Some software install for user01",
							},
							&mockregistry.MockValue{
								VName:       "DisplayVersion",
								VDataString: "1.01.1",
							},
						},
					},
					// System-related installs.
					regUninstallRootDefault: &mockregistry.MockKey{
						KName:    "Uninstall",
						KSubkeys: []registry.Key{},
					},
					regUninstallRootWow64: &mockregistry.MockKey{
						KName:    "Uninstall",
						KSubkeys: []registry.Key{},
					},
				},
			},
			want: []*extractor.Package{
				{Name: "Some software install for user00", Version: "1.00.1", PURLType: "windows"},
				{Name: "GooGet - Some software install for user01", Version: "1.01.1", PURLType: purl.TypeGooget},
			},
		},
		{
			name:    "empty_registry_returns_error",
			reg:     &mockregistry.MockRegistry{},
			want:    []*extractor.Package{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Configuration{mockregistry.NewOpener(tc.reg)}
			e := New(cfg)
			got, err := e.Extract(context.Background(), nil)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Extract() returned an unexpected error: %v", err)
			}

			if tc.wantErr == true {
				return
			}

			if diff := cmp.Diff(inventory.Inventory{Packages: tc.want}, got); diff != "" {
				t.Errorf("Extract() returned an unexpected diff (-want +got): %v", diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want *purl.PackageURL
	}{
		{
			name: "googet_package",
			pkg:  &extractor.Package{Name: "GooGet - some package", Version: "1.0.0", PURLType: purl.TypeGooget},
			want: &purl.PackageURL{Type: purl.TypeGooget, Name: "GooGet - some package", Version: "1.0.0"},
		},
		{
			name: "normal_windows_package",
			pkg:  &extractor.Package{Name: "Some software", Version: "1.0.0", PURLType: "windows"},
			want: &purl.PackageURL{Type: purl.TypeGeneric, Namespace: "microsoft", Name: "Some software", Version: "1.0.0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := Extractor{}
			got := e.ToPURL(tc.pkg)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToPURL(%v) returned an unexpected diff (-want +got): %v", tc.pkg, diff)
			}
		})
	}
}
