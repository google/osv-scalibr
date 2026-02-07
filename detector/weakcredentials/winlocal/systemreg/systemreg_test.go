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

package systemreg

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/testing/mockregistry"
)

func TestNewFromFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "File is missing registry magic",
			path:    "/dev/null",
			wantErr: true,
		},
		{
			name:    "Fails when file does not exist",
			path:    "/some/non/existing/file",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewFromFile(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewFromFile(%q) error: got: %v, want: %v", tc.path, err, tc.wantErr)
			}
		})
	}
}

func TestSyskey(t *testing.T) {
	tests := []struct {
		name        string
		registry    *mockregistry.MockRegistry
		want        []byte
		wantErr     bool
		wantErrText string
	}{
		{
			name: "Parses_syskey_correctly",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`Select`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "Current",
								VData: []byte{0x01},
							},
						},
					},
					`ControlSet001\Control\Lsa\JD`: &mockregistry.MockKey{
						KClassName: "\x32\x00\x35\x00\x33\x00\x35\x00\x39\x00\x33\x00\x64\x00\x64\x00",
					},
					`ControlSet001\Control\Lsa\Skew1`: &mockregistry.MockKey{
						KClassName: "\x61\x00\x65\x00\x39\x00\x33\x00\x34\x00\x37\x00\x30\x00\x30\x00",
					},
					`ControlSet001\Control\Lsa\GBG`: &mockregistry.MockKey{
						KClassName: "\x38\x00\x38\x00\x31\x00\x33\x00\x39\x00\x64\x00\x34\x00\x35\x00",
					},
					`ControlSet001\Control\Lsa\Data`: &mockregistry.MockKey{
						KClassName: "\x31\x00\x36\x00\x62\x00\x64\x00\x33\x00\x65\x00\x33\x00\x33\x00",
					},
				},
			},
			want: []byte("\x88\x93\xae\x93\x45\x13\xbd\xdd\x25\x47\x35\x16\x3e\x9d\x33\x00"),
		},
		{
			name: "Parses_syskey_correctly_with_different_control_set",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`Select`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "Current",
								VData: []byte{0x02},
							},
						},
					},
					`ControlSet002\Control\Lsa\JD`: &mockregistry.MockKey{
						KClassName: "\x32\x00\x35\x00\x33\x00\x35\x00\x39\x00\x33\x00\x64\x00\x64\x00",
					},
					`ControlSet002\Control\Lsa\Skew1`: &mockregistry.MockKey{
						KClassName: "\x61\x00\x65\x00\x39\x00\x33\x00\x34\x00\x37\x00\x30\x00\x30\x00",
					},
					`ControlSet002\Control\Lsa\GBG`: &mockregistry.MockKey{
						KClassName: "\x38\x00\x38\x00\x31\x00\x33\x00\x39\x00\x64\x00\x34\x00\x35\x00",
					},
					`ControlSet002\Control\Lsa\Data`: &mockregistry.MockKey{
						KClassName: "\x31\x00\x36\x00\x62\x00\x64\x00\x33\x00\x65\x00\x33\x00\x33\x00",
					},
				},
			},
			want: []byte("\x88\x93\xae\x93\x45\x13\xbd\xdd\x25\x47\x35\x16\x3e\x9d\x33\x00"),
		},
		{
			name: "Parts_of_the_syskey_are_missing",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`Select`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "Current",
								VData: []byte{0x01},
							},
						},
					},
					`ControlSet001\Control\Lsa\JD`: &mockregistry.MockKey{
						KClassName: "\x32\x00\x35\x00\x33\x00\x35\x00\x39\x00\x33\x00\x64\x00\x64\x00",
					},
				},
			},
			wantErr:     true,
			wantErrText: `failed to open key`,
		},
		{
			name: "The_key_does_not_decode_as_hexadecimal",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`Select`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "Current",
								VData: []byte{0x01},
							},
						},
					},
					`ControlSet001\Control\Lsa\JD`: &mockregistry.MockKey{
						KClassName: "\x32\xFF\x35\xFF\x33\xFF\x35\xFF\x39\xFF\x33\xFF\x64\xFF\x64\xFF",
					},
					`ControlSet001\Control\Lsa\Skew1`: &mockregistry.MockKey{
						KClassName: "\x61\x00\x65\x00\x39\x00\x33\x00\x34\x00\x37\x00\x30\x00\x30\x00",
					},
					`ControlSet001\Control\Lsa\GBG`: &mockregistry.MockKey{
						KClassName: "\x38\x00\x38\x00\x31\x00\x33\x00\x39\x00\x64\x00\x34\x00\x35\x00",
					},
					`ControlSet001\Control\Lsa\Data`: &mockregistry.MockKey{
						KClassName: "\x31\x00\x36\x00\x62\x00\x64\x00\x33\x00\x65\x00\x33\x00\x33\x00",
					},
				},
			},
			wantErr:     true,
			wantErrText: `encoding/hex: invalid byte: U+00EF 'ï'`,
		},
		{
			name: "Select_registry_key_not_found",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{},
			},
			wantErr:     true,
			wantErrText: `failed to open key`,
		},
		{
			name: "Current_control_set_not_found",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`Select`: &mockregistry.MockKey{},
				},
			},
			wantErr:     true,
			wantErrText: errNoCurrentControlSet.Error(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sysreg := &SystemRegistry{tc.registry}
			got, err := sysreg.Syskey()

			if (err != nil) != tc.wantErr {
				t.Errorf("Syskey() unexpected error: %v", err)
			}

			if tc.wantErr {
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf("Syskey() unexpected error: got: %v, want: %v", err.Error(), tc.wantErrText)
				}

				return
			}

			if !slices.Equal(got, tc.want) {
				t.Errorf("Syskey() unexpected result: got: %v, want: %v", got, tc.want)
			}
		})
	}
}
