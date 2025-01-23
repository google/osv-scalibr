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

package samreg

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/testing/mockregistry"
)

func TestNewFromFile(t *testing.T) {
	tests := []struct {
		name        string
		filepath    string
		onGOOS      string
		wantErr     bool
		wantErrText string
	}{
		{
			name:        "file_does_not_exist_returns_error_on_windows",
			filepath:    "/some/path/that/does/not/exist",
			onGOOS:      "windows",
			wantErr:     true,
			wantErrText: "The system cannot find the path specified",
		},
		{
			name:        "file_does_not_exist_returns_error_on_linux",
			filepath:    "/some/path/that/does/not/exist",
			onGOOS:      "linux",
			wantErr:     true,
			wantErrText: "no such file or directory",
		},
		{
			name:        "file_not_a_registry_returns_error_on_windows",
			filepath:    "C:\\Windows\\System32\\cmd.exe",
			onGOOS:      "windows",
			wantErr:     true,
			wantErrText: "File does not have registry magic.",
		},
		{
			name:        "file_not_a_registry_returns_error_on_linux",
			filepath:    "/dev/zero",
			onGOOS:      "linux",
			wantErr:     true,
			wantErrText: "File does not have registry magic.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.onGOOS != runtime.GOOS {
				t.Skipf("Skipping test %q for %q", tc.name, tc.onGOOS)
			}

			_, err := NewFromFile(tc.filepath)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewFromFile(%q) unexpected error: %v", tc.filepath, err)
			}

			if tc.wantErr {
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf("NewFromFile(%q) unexpected error, got: %v, want: %v", tc.filepath, err, tc.wantErrText)
				}

				return
			}
		})
	}
}

func TestUserRIDs(t *testing.T) {
	tests := []struct {
		name     string
		registry *mockregistry.MockRegistry
		want     []string
		wantErr  error
	}{
		{
			name: "list_users_from_SAM_succeeds",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account\Users`: &mockregistry.MockKey{
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "Names",
							},
							&mockregistry.MockKey{
								KName: "000003E9",
							},
							&mockregistry.MockKey{
								KName: "000001F4",
							},
							&mockregistry.MockKey{
								KName: "000003EA",
							},
						},
					},
				},
			},
			want: []string{"000003E9", "000001F4", "000003EA"},
		},
		{
			name: "no_users_in_SAM_returns_empty_list",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account\Users`: &mockregistry.MockKey{
						KSubkeys: []registry.Key{
							&mockregistry.MockKey{
								KName: "Names",
							},
						},
					},
				},
			},
			want: []string{},
		},
		{
			name:     "missing_user_key_returns_error",
			registry: &mockregistry.MockRegistry{},
			wantErr:  errFailedToParseUsers,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sam := SAMRegistry{tc.registry}

			got, err := sam.UsersRIDs()
			if err != tc.wantErr {
				t.Fatalf("UserRIDs() returned an unexpected error: %v", err)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("UserRIDs() returned an unexpected diff (-want +got): %v", diff)
			}
		})
	}
}

func TestUserInfo(t *testing.T) {
	tests := []struct {
		name        string
		registry    *mockregistry.MockRegistry
		rid         string
		wantErr     bool
		wantErrText string
	}{
		{
			name: "user_info_structure_parses_correctly",
			rid:  "000001F4",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account\Users\000001F4`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "V",
								VData: []byte(strings.Repeat("\x00", 0xCC)),
							},
							&mockregistry.MockValue{
								VName: "F",
								VData: []byte(""),
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:        "user_specific_key_missing_returns_error",
			rid:         "000001F4",
			registry:    &mockregistry.MockRegistry{},
			wantErr:     true,
			wantErrText: "SAM hive: failed to load user registry for RID",
		},
		{
			name: "missing_v_structure_returns_error",
			rid:  "000001F4",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account\Users\000001F4`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "F",
								VData: []byte(""),
							},
						},
					},
				},
			},
			wantErr:     true,
			wantErrText: "SAM hive: failed to find V or F structures for RID",
		},
		{
			name: "V_structure_parse_failure_returns_error",
			rid:  "000001F4",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account\Users\000001F4`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "V",
								VData: []byte("\x00"),
							},
							&mockregistry.MockValue{
								VName: "F",
								VData: []byte(""),
							},
						},
					},
				},
			},
			wantErr:     true,
			wantErrText: "unexpected EOF",
		},
		{
			name: "missing_F_structure_returns_error",
			rid:  "000001F4",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account\Users\000001F4`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "V",
								VData: []byte(strings.Repeat("\x00", 0xCC)),
							},
						},
					},
				},
			},
			wantErr:     true,
			wantErrText: "SAM hive: failed to find V or F structures for RID",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sam := SAMRegistry{tc.registry}

			_, err := sam.UserInfo(tc.rid)
			if (err != nil) != tc.wantErr {
				t.Fatalf("UserInfo(%q) returned an unexpected error: %v", tc.rid, err)
			}

			if tc.wantErr {
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf("UserInfo(%q) unexpected error, got: %v, want: %v", tc.rid, err, tc.wantErrText)
				}

				return
			}
		})
	}
}

func TestDeriveSyskey(t *testing.T) {
	tests := []struct {
		name     string
		registry *mockregistry.MockRegistry
		syskey   []byte
		want     []byte
		wantErr  error
	}{
		{
			name: "syskey_derivation_succeeds",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "F",
								VData: []byte("\x02\x00\x01\x00\x00\x00\x00\x00\x40\x15\x3b\x97\x46\x9f\xce\x01\x26\x00\x00\x00\x00\x00\x00\x00\x00\x80\xa6\x0a\xff\xde\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\xcc\x1d\xcf\xfb\xff\xff\xff\x00\xcc\x1d\xcf\xfb\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xe9\x03\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x38\x00\x00\x00\x23\x7e\xe9\x12\xa7\x34\xbf\x93\x18\x6e\xaa\xc1\x83\x07\x59\xa1\xd6\x96\xa6\x99\x6b\xa9\x41\x61\x44\x92\xb0\xfb\xd0\x0a\xe9\xa6\x37\xd6\x7c\xc6\x99\x2b\xc7\x12\xfe\x22\xa0\x17\x71\xce\xd3\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x38\x00\x00\x00\x3d\xfe\xe0\xd7\x20\xeb\x39\xc1\x44\x1c\x8d\x05\x29\xd6\x83\x47\x92\xa2\x29\x38\xfc\x9e\xa7\x29\xa9\x36\x7d\x4a\xfc\x6c\xe1\xb3\xd3\xac\xd4\xac\xe2\x5b\xab\xf9\xf8\x3f\x09\xe1\x91\x1a\x7d\xda\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"),
							},
						},
					},
				},
			},
			syskey: []byte("\x88\x93\xae\x93\x45\x13\xbd\xdd\x25\x47\x35\x16\x3e\x9d\x33\x00"),
			want:   []byte("\x3d\x21\x2c\xe8\xa2\xda\x83\x43\xbd\xad\x1e\xf2\xcf\xb6\xb3\x1c"),
		},
		{
			name: "missing_domain_key_returns_error",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{},
			},
			wantErr: errFailedToOpenDomain,
		},
		{
			name: "missing_domainF_structure_returns_error",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account`: &mockregistry.MockKey{
						KValues: []registry.Value{},
					},
				},
			},
			wantErr: errFailedToParseDomainF,
		},
		{
			name: "error_from_derivation_propagates",
			registry: &mockregistry.MockRegistry{
				Keys: map[string]registry.Key{
					`SAM\Domains\Account`: &mockregistry.MockKey{
						KValues: []registry.Value{
							&mockregistry.MockValue{
								VName: "F",
								VData: []byte(""),
							},
						},
					},
				},
			},
			wantErr: errDomainFTooShort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sam := SAMRegistry{tc.registry}

			got, err := sam.DeriveSyskey(tc.syskey)
			if err != tc.wantErr {
				t.Errorf("DeriveSyskey(%x) unexpected error, got: %v, want: %v", tc.syskey, err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("DeriveSyskey(%x) returned an unexpected diff (-want +got): %v", tc.syskey, diff)
			}
		})
	}
}
