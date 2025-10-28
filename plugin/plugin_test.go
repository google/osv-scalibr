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

package plugin_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	"github.com/google/osv-scalibr/extractor/filesystem/os/snap"
	"github.com/google/osv-scalibr/plugin"
)

type fakePlugin struct {
	reqs *plugin.Capabilities
}

func (fakePlugin) Name() string                         { return "fake-plugin" }
func (fakePlugin) Version() int                         { return 0 }
func (p fakePlugin) Requirements() *plugin.Capabilities { return p.reqs }

func TestValidateRequirements(t *testing.T) {
	testCases := []struct {
		desc       string
		pluginReqs *plugin.Capabilities
		capabs     *plugin.Capabilities
		wantErr    error
	}{
		{
			desc:       "No requirements",
			pluginReqs: &plugin.Capabilities{},
			capabs:     &plugin.Capabilities{},
			wantErr:    nil,
		},
		{
			desc:       "All requirements satisfied",
			pluginReqs: &plugin.Capabilities{Network: plugin.NetworkOnline, DirectFS: true},
			capabs:     &plugin.Capabilities{Network: plugin.NetworkOnline, DirectFS: true},
			wantErr:    nil,
		},
		{
			desc:       "One requirement not satisfied",
			pluginReqs: &plugin.Capabilities{Network: plugin.NetworkOnline, DirectFS: true},
			capabs:     &plugin.Capabilities{Network: plugin.NetworkOnline, DirectFS: false},
			wantErr:    cmpopts.AnyError,
		},
		{
			desc:       "No requirement satisfied",
			pluginReqs: &plugin.Capabilities{Network: plugin.NetworkOnline, DirectFS: true},
			capabs:     &plugin.Capabilities{Network: plugin.NetworkOffline, DirectFS: false},
			wantErr:    cmpopts.AnyError,
		},
		{
			desc:       "Any network 1",
			pluginReqs: &plugin.Capabilities{Network: plugin.NetworkAny},
			capabs:     &plugin.Capabilities{Network: plugin.NetworkOffline},
			wantErr:    nil,
		},
		{
			desc:       "Any network 2",
			pluginReqs: &plugin.Capabilities{Network: plugin.NetworkAny},
			capabs:     &plugin.Capabilities{Network: plugin.NetworkOnline},
			wantErr:    nil,
		},
		{
			desc:       "Wrong OS",
			pluginReqs: &plugin.Capabilities{OS: plugin.OSLinux},
			capabs:     &plugin.Capabilities{OS: plugin.OSWindows},
			wantErr:    cmpopts.AnyError,
		},
		{
			desc:       "Unix OS not satisfied",
			pluginReqs: &plugin.Capabilities{OS: plugin.OSUnix},
			capabs:     &plugin.Capabilities{OS: plugin.OSWindows},
			wantErr:    cmpopts.AnyError,
		},
		{
			desc:       "Unix OS satisfied",
			pluginReqs: &plugin.Capabilities{OS: plugin.OSUnix},
			capabs:     &plugin.Capabilities{OS: plugin.OSMac},
			wantErr:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := fakePlugin{reqs: tc.pluginReqs}
			err := plugin.ValidateRequirements(p, tc.capabs)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("plugin.ValidateRequirements(%v, %v) got error: %v, want: %v\n", tc.pluginReqs, tc.capabs, err, tc.wantErr)
			}
		})
	}
}

func TestFilterByCapabilities(t *testing.T) {
	capab := &plugin.Capabilities{OS: plugin.OSLinux}
	pls := []plugin.Plugin{snap.NewDefault(), homebrew.New()}
	got := plugin.FilterByCapabilities(pls, capab)
	if len(got) != 1 {
		t.Fatalf("plugin.FilterCapabilities(%v, %v): want 1 plugin, got %d", pls, capab, len(got))
	}
	gotName := got[0].Name()
	wantName := "os/snap" // os/homebrew is for Mac only
	if gotName != wantName {
		t.Fatalf("plugin.FilterCapabilities(%v, %v): want plugin %q, got %q", pls, capab, wantName, gotName)
	}
}

func TestString(t *testing.T) {
	testCases := []struct {
		desc string
		s    *plugin.ScanStatus
		want string
	}{
		{
			desc: "Successful scan",
			s:    &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
			want: "SUCCEEDED",
		},
		{
			desc: "Partially successful scan",
			s:    &plugin.ScanStatus{Status: plugin.ScanStatusPartiallySucceeded},
			want: "PARTIALLY_SUCCEEDED",
		},
		{
			desc: "Failed scan",
			s:    &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: "failure"},
			want: "FAILED: failure",
		},
		{
			desc: "Unspecified status",
			s:    &plugin.ScanStatus{},
			want: "UNSPECIFIED",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := tc.s.String()
			if got != tc.want {
				t.Errorf("%v.String(): Got %s, want %s", tc.s, got, tc.want)
			}
		})
	}
}

func TestDedupeStatuses(t *testing.T) {
	testCases := []struct {
		desc string
		s    []*plugin.Status
		want []*plugin.Status
	}{
		{
			desc: "Separate_plugins",
			s: []*plugin.Status{
				{
					Name:   "plugin1",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
				{
					Name:   "plugin2",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
			},
			want: []*plugin.Status{
				{
					Name:   "plugin1",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
				{
					Name:   "plugin2",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
			},
		},
		{
			desc: "Both_successful",
			s: []*plugin.Status{
				{
					Name:   "plugin1",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
				{
					Name:   "plugin1",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
			},
			want: []*plugin.Status{
				{
					Name:   "plugin1",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
			},
		},
		{
			desc: "One_success_one_partial_success",
			s: []*plugin.Status{
				{
					Name:   "plugin1",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusPartiallySucceeded,
						FailureReason: "reason",
					},
				},
			},
			want: []*plugin.Status{
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusPartiallySucceeded,
						FailureReason: "reason",
					},
				},
			},
		},
		{
			desc: "One_success_one_failure",
			s: []*plugin.Status{
				{
					Name:   "plugin1",
					Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusFailed,
						FailureReason: "reason",
					},
				},
			},
			want: []*plugin.Status{
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusFailed,
						FailureReason: "reason",
					},
				},
			},
		},
		{
			desc: "One_partial_success_one_failure",
			s: []*plugin.Status{
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusPartiallySucceeded,
						FailureReason: "reason1",
					},
				},
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusFailed,
						FailureReason: "reason2",
					},
				},
			},
			want: []*plugin.Status{
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusFailed,
						FailureReason: "reason1\nreason2",
					},
				},
			},
		},
		{
			desc: "File_errors_combined",
			s: []*plugin.Status{
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusFailed,
						FailureReason: "encountered 1 error(s) while running plugin; check file-specific errors for details",
						FileErrors: []*plugin.FileError{
							{FilePath: "file1", ErrorMessage: "msg1"},
						},
					},
				},
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusFailed,
						FailureReason: "encountered 1 error(s) while running plugin; check file-specific errors for details",
						FileErrors: []*plugin.FileError{
							{FilePath: "file2", ErrorMessage: "msg2"},
						},
					},
				},
			},
			want: []*plugin.Status{
				{
					Name: "plugin1",
					Status: &plugin.ScanStatus{
						Status:        plugin.ScanStatusFailed,
						FailureReason: "encountered 2 error(s) while running plugin; check file-specific errors for details",
						FileErrors: []*plugin.FileError{
							{FilePath: "file1", ErrorMessage: "msg1"},
							{FilePath: "file2", ErrorMessage: "msg2"},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := plugin.DedupeStatuses(tc.s)
			sort := func(a, b *plugin.Status) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tc.want, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Fatalf("plugin.DedupeStatuses(%v) (-want +got):\n%s", tc.s, diff)
			}
		})
	}
}
