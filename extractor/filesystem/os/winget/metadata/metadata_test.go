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

package metadata_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/os/winget/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestSetProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		p    *pb.Package
		want *pb.Package
	}{
		{
			desc: "nil_metadata",
			m:    nil,
			p:    &pb.Package{Name: "some-package"},
			want: &pb.Package{Name: "some-package"},
		},
		{
			desc: "nil_package",
			m: &metadata.Metadata{
				Name: "Git",
			},
			p:    nil,
			want: nil,
		},
		{
			desc: "set_metadata",
			m: &metadata.Metadata{
				Name: "Git",
				ID:   "Git.Git",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_WingetMetadata{
					WingetMetadata: &pb.WingetPackageMetadata{
						Name: "Git",
						Id:   "Git.Git",
					},
				},
			},
		},
		{
			desc: "override_metadata",
			m: &metadata.Metadata{
				Name: "Visual Studio Code",
				ID:   "Microsoft.VisualStudioCode",
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_WingetMetadata{
					WingetMetadata: &pb.WingetPackageMetadata{
						Name: "Git",
						Id:   "Git.Git",
					},
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_WingetMetadata{
					WingetMetadata: &pb.WingetPackageMetadata{
						Name: "Visual Studio Code",
						Id:   "Microsoft.VisualStudioCode",
					},
				},
			},
		},
		{
			desc: "set_all_fields",
			m: &metadata.Metadata{
				Name:     "Git",
				ID:       "Git.Git",
				Version:  "2.50.1",
				Moniker:  "git",
				Channel:  "stable",
				Tags:     []string{"git", "vcs"},
				Commands: []string{"git"},
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_WingetMetadata{
					WingetMetadata: &pb.WingetPackageMetadata{
						Name:     "Git",
						Id:       "Git.Git",
						Version:  "2.50.1",
						Moniker:  "git",
						Channel:  "stable",
						Tags:     []string{"git", "vcs"},
						Commands: []string{"git"},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := proto.Clone(tc.p).(*pb.Package)
			tc.m.SetProto(p)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, p, opts...); diff != "" {
				t.Errorf("Metadata{%+v}.SetProto(%+v): (-want +got):\n%s", tc.m, tc.p, diff)
			}

			// Test the reverse conversion for completeness.

			if tc.p == nil && tc.want == nil {
				return
			}

			got := metadata.ToStruct(p.GetWingetMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetWingetMetadata(), diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.WingetPackageMetadata
		want *metadata.Metadata
	}{
		{
			desc: "nil",
			m:    nil,
			want: nil,
		},
		{
			desc: "some_fields",
			m: &pb.WingetPackageMetadata{
				Name: "Git",
				Id:   "Git.Git",
			},
			want: &metadata.Metadata{
				Name: "Git",
				ID:   "Git.Git",
			},
		},
		{
			desc: "all_fields",
			m: &pb.WingetPackageMetadata{
				Name:     "Git",
				Id:       "Git.Git",
				Version:  "2.50.1",
				Moniker:  "git",
				Channel:  "stable",
				Tags:     []string{"git", "vcs"},
				Commands: []string{"git"},
			},
			want: &metadata.Metadata{
				Name:     "Git",
				ID:       "Git.Git",
				Version:  "2.50.1",
				Moniker:  "git",
				Channel:  "stable",
				Tags:     []string{"git", "vcs"},
				Commands: []string{"git"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", tc.m, diff)
			}

			if tc.m == nil {
				return
			}

			// Test the reverse conversion for completeness.

			gotP := &pb.Package{}
			wantP := &pb.Package{
				Metadata: &pb.Package_WingetMetadata{
					WingetMetadata: tc.m,
				},
			}

			tc.want.SetProto(gotP)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(wantP, gotP, opts...); diff != "" {
				t.Errorf("Metadata{%+v}.SetProto(): (-want +got):\n%s", tc.want, diff)
			}
		})
	}
}
