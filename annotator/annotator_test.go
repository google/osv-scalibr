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

package annotator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/cachedir"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

type succeedingAnnotator struct{}

func (succeedingAnnotator) Name() string                       { return "succeeding-annotator" }
func (succeedingAnnotator) Version() int                       { return 1 }
func (succeedingAnnotator) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (succeedingAnnotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	return nil
}

type failingAnnotator struct{}

func (failingAnnotator) Name() string                       { return "failing-annotator" }
func (failingAnnotator) Version() int                       { return 2 }
func (failingAnnotator) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (failingAnnotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	return errors.New("some error")
}

type recordingAnnotator struct {
	seenPackages []*extractor.Package
}

func (r *recordingAnnotator) Name() string { return "recording-annotator" }
func (r *recordingAnnotator) Version() int { return 1 }
func (r *recordingAnnotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{RunningSystem: true}
}
func (r *recordingAnnotator) Annotate(ctx context.Context, input *annotator.ScanInput, inv *inventory.Inventory) error {
	r.seenPackages = inv.Packages
	return nil
}

func TestRun(t *testing.T) {
	inv := &inventory.Inventory{
		Packages: []*extractor.Package{
			{Name: "package1", Version: "1.0", Location: extractor.LocationFromPath("tmp/package.json")},
		},
	}

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	anno, err := cachedir.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		desc    string
		cfg     *annotator.Config
		inv     *inventory.Inventory
		want    []*plugin.Status
		wantErr error
		wantInv *inventory.Inventory // Inventory after annotation.
		rec     *recordingAnnotator
	}{
		{
			desc: "no_annotators",
			cfg:  &annotator.Config{},
			want: nil,
		},
		{
			desc: "annotator_modifies_inventory",
			cfg: &annotator.Config{
				Annotators: []annotator.Annotator{anno},
			},
			inv: inv,
			want: []*plugin.Status{
				{Name: "vex/cachedir", Version: 0, Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
			},
			wantInv: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "package1",
						Version:  "1.0",
						Location: extractor.LocationFromPath("tmp/package.json"),
						ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
							Plugin:          cachedir.Name,
							Justification:   vex.ComponentNotPresent,
							MatchesAllVulns: true,
						}},
					},
				},
			},
		},
		{
			desc: "annotator_fails",
			cfg: &annotator.Config{
				Annotators: []annotator.Annotator{&failingAnnotator{}},
			},
			want: []*plugin.Status{
				{Name: "failing-annotator", Version: 2, Status: &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: "some error"}},
			},
		},
		{
			desc: "one_fails_one_succeeds",
			cfg: &annotator.Config{
				Annotators: []annotator.Annotator{&succeedingAnnotator{}, &failingAnnotator{}},
			},
			want: []*plugin.Status{
				{Name: "succeeding-annotator", Version: 1, Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
				{Name: "failing-annotator", Version: 2, Status: &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: "some error"}},
			},
		},
		{
			desc: "filters_embedded_fs_packages_for_running_system_annotator",
			rec:  &recordingAnnotator{},
			cfg:  nil,
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "host-package",
						Version:  "1.0",
						Location: extractor.LocationFromPath("file.txt"),
					},
					{
						Name:     "embedded-package-unix",
						Version:  "2.0",
						Location: extractor.LocationFromPath("file.vmdk:1:file.txt"),
					},
					{
						Name:     "embedded-package-windows",
						Version:  "3.0",
						Location: extractor.LocationFromPath("C:\\file.vmdk:1:file.txt"),
					},
				},
			},
			want: []*plugin.Status{
				{
					Name:    "recording-annotator",
					Version: 1,
					Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				},
			},
			wantInv: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "host-package",
						Version:  "1.0",
						Location: extractor.LocationFromPath("file.txt"),
					},
					{
						Name:     "embedded-package-unix",
						Version:  "2.0",
						Location: extractor.LocationFromPath("file.vmdk:1:file.txt"),
					},
					{
						Name:     "embedded-package-windows",
						Version:  "3.0",
						Location: extractor.LocationFromPath("C:\\file.vmdk:1:file.txt"),
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			// Deep copy the inventory to avoid modifying the original inventory that is used in other tests.
			inv := copier.Copy(tc.inv).(*inventory.Inventory)

			if tc.rec != nil && tc.cfg == nil {
				tc.cfg = &annotator.Config{
					Annotators: []annotator.Annotator{tc.rec},
				}
			}

			got, err := annotator.Run(t.Context(), tc.cfg, inv)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("Run(%+v) error: got %v, want %v\n", tc.cfg, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Run(%+v) returned an unexpected diff of statuses (-want +got): %v", tc.cfg, diff)
			}
			if diff := cmp.Diff(tc.wantInv, inv); diff != "" {
				t.Errorf("Run(%+v) returned an unexpected diff of mutated inventory (-want +got): %v", tc.cfg, diff)
			}
			// Verify filtering behavior
			if tc.rec != nil {
				if len(tc.rec.seenPackages) != 1 || tc.rec.seenPackages[0].Name != "host-package" {
					t.Errorf("expected only host package, got %+v", tc.rec.seenPackages)
				}
			}
		})
	}
}
