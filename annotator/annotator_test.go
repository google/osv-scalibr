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
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	"google.golang.org/protobuf/proto"
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

func TestRun(t *testing.T) {
	inv := &inventory.Inventory{
		Packages: []*extractor.Package{
			{Name: "package1", Version: "1.0", Locations: []string{"tmp/package.json"}},
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
						Name:      "package1",
						Version:   "1.0",
						Locations: []string{"tmp/package.json"},
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
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			// Deep copy the inventory to avoid modifying the original inventory that is used in other tests.
			inv := copier.Copy(tc.inv).(*inventory.Inventory)
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
		})
	}
}
