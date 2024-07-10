// Copyright 2024 Google LLC
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

package dismpatch

import (
	_ "embed"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch/dismparser"
)

func TestInventoryFromOutput(t *testing.T) {
	dismTestData, err := os.ReadFile("dismparser/testdata/dism_testdata.txt")
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	tests := []struct {
		desc    string
		flavor  string
		output  string
		want    []*extractor.Inventory
		wantErr error
	}{
		{
			desc:   "Valid test data returns inventory",
			flavor: "server",
			output: string(dismTestData),
			want: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "windows_server_2019",
					Version:   "10.0.17763.3406",
					Locations: []string{"cmd-dism-osver"},
				},
				&extractor.Inventory{
					Name:      "Microsoft-Windows-FodMetadata-Package~31bf3856ad364e35~amd64~~10.0.17763.1",
					Version:   "10.0.17763.1",
					Locations: []string{"cmd-dism"},
				},
				&extractor.Inventory{
					Name:      "Package_for_KB4470788~31bf3856ad364e35~amd64~~17763.164.1.1",
					Version:   "17763.164.1.1",
					Locations: []string{"cmd-dism"},
				},
				&extractor.Inventory{
					Name:      "Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.3406.1.5",
					Version:   "17763.3406.1.5",
					Locations: []string{"cmd-dism"},
				},
				&extractor.Inventory{
					Name:      "Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.379.1.11",
					Version:   "17763.379.1.11",
					Locations: []string{"cmd-dism"},
				},
				&extractor.Inventory{
					Name:      "Package_for_ServicingStack_3232~31bf3856ad364e35~amd64~~17763.3232.1.1",
					Version:   "17763.3232.1.1",
					Locations: []string{"cmd-dism"},
				},
				&extractor.Inventory{
					Name:      "Microsoft-Windows-WordPad-FoD-Package~31bf3856ad364e35~wow64~en-US~10.0.19041.1",
					Version:   "10.0.19041.1",
					Locations: []string{"cmd-dism"},
				},
			},
			wantErr: nil,
		},
		{
			desc:    "Empty output returns parsing error",
			flavor:  "server",
			output:  "",
			want:    nil,
			wantErr: dismparser.ErrParsingError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, gotErr := inventoryFromOutput(tc.flavor, tc.output)
			if gotErr != tc.wantErr {
				t.Fatalf("inventoryFromOutput(%q, %q) returned an unexpected error: %v", tc.flavor, tc.output, gotErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("inventoryFromOutput(%q, %q) returned an unexpected diff (-want +got): %v", tc.flavor, tc.output, diff)
			}
		})
	}
}
