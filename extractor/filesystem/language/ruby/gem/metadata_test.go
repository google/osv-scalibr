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

package gem_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gem"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *gem.RubyGemMetadata
		want *pb.RubyGemMetadata
	}{
		{
			desc: "nil metadata",
			m:    nil,
			want: nil,
		},
		{
			desc: "minimal metadata",
			m: &gem.RubyGemMetadata{
				Authors:     []string{"Jane Doe"},
				Description: "A gem description",
				Homepage:    "https://example.com/gem",
				Licenses:    []string{"MIT"},
				Platform:    "ruby",
				Summary:     "A short summary",
			},
			want: &pb.RubyGemMetadata{
				Authors:     []string{"Jane Doe"},
				Description: "A gem description",
				Homepage:    "https://example.com/gem",
				Licenses:    []string{"MIT"},
				Platform:    "ruby",
				Summary:     "A short summary",
			},
		},
		{
			desc: "metadata with dependencies",
			m: &gem.RubyGemMetadata{
				Authors:     []string{"Jane Doe", "John Smith"},
				Description: "A gem with dependencies",
				Homepage:    "https://example.com/gem",
				Licenses:    []string{"MIT", "Apache-2.0"},
				Platform:    "x86_64-linux",
				Summary:     "Gem summary",
				Dependencies: []*gem.Dependency{
					{
						Name: "rake",
						Type: ":runtime",
						Requirement: &gem.Requirement{
							Requirements: []gem.RequirementConstraint{
								{Operator: ">=", Version: "12.0"},
								{Operator: "<", Version: "14.0"},
							},
						},
						Prerelease: false,
					},
					{
						Name: "rspec",
						Type: ":development",
						VersionRequirements: &gem.Requirement{
							Requirements: []gem.RequirementConstraint{
								{Operator: "~>", Version: "3.10"},
							},
						},
						Prerelease: true,
					},
				},
			},
			want: &pb.RubyGemMetadata{
				Authors:     []string{"Jane Doe", "John Smith"},
				Description: "A gem with dependencies",
				Homepage:    "https://example.com/gem",
				Licenses:    []string{"MIT", "Apache-2.0"},
				Platform:    "x86_64-linux",
				Summary:     "Gem summary",
				Dependencies: []*pb.RubyGemMetadata_Dependency{
					{
						Name: "rake",
						Type: ":runtime",
						Requirements: []*pb.RubyGemMetadata_Dependency_RequirementConstraint{
							{Operator: ">=", Version: "12.0"},
							{Operator: "<", Version: "14.0"},
						},
						Prerelease: false,
					},
					{
						Name: "rspec",
						Type: ":development",
						Requirements: []*pb.RubyGemMetadata_Dependency_RequirementConstraint{
							{Operator: "~>", Version: "3.10"},
						},
						Prerelease: true,
					},
				},
			},
		},
		{
			desc: "metadata with nil dependency in slice",
			m: &gem.RubyGemMetadata{
				Authors: []string{"Jane Doe"},
				Dependencies: []*gem.Dependency{
					nil,
					{
						Name: "rake",
						Type: ":runtime",
					},
				},
			},
			want: &pb.RubyGemMetadata{
				Authors: []string{"Jane Doe"},
				Dependencies: []*pb.RubyGemMetadata_Dependency{
					{
						Name: "rake",
						Type: ":runtime",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := gem.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("gem.ToProto(%+v): (-want +got):\n%s", tc.m, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		p    *pb.RubyGemMetadata
		want *gem.RubyGemMetadata
	}{
		{
			desc: "nil proto",
			p:    nil,
			want: nil,
		},
		{
			desc: "minimal proto",
			p: &pb.RubyGemMetadata{
				Authors:     []string{"Jane Doe"},
				Description: "A gem description",
				Homepage:    "https://example.com/gem",
				Licenses:    []string{"MIT"},
				Platform:    "ruby",
				Summary:     "A short summary",
			},
			want: &gem.RubyGemMetadata{
				Authors:     []string{"Jane Doe"},
				Description: "A gem description",
				Homepage:    "https://example.com/gem",
				Licenses:    []string{"MIT"},
				Platform:    "ruby",
				Summary:     "A short summary",
			},
		},
		{
			desc: "proto with dependencies",
			p: &pb.RubyGemMetadata{
				Authors:     []string{"Jane Doe", "John Smith"},
				Description: "A gem with dependencies",
				Homepage:    "https://example.com/gem",
				Licenses:    []string{"MIT", "Apache-2.0"},
				Platform:    "x86_64-linux",
				Summary:     "Gem summary",
				Dependencies: []*pb.RubyGemMetadata_Dependency{
					{
						Name: "rake",
						Type: ":runtime",
						Requirements: []*pb.RubyGemMetadata_Dependency_RequirementConstraint{
							{Operator: ">=", Version: "12.0"},
							{Operator: "<", Version: "14.0"},
						},
						Prerelease: false,
					},
				},
			},
			want: &gem.RubyGemMetadata{
				Authors:     []string{"Jane Doe", "John Smith"},
				Description: "A gem with dependencies",
				Homepage:    "https://example.com/gem",
				Licenses:    []string{"MIT", "Apache-2.0"},
				Platform:    "x86_64-linux",
				Summary:     "Gem summary",
				Dependencies: []*gem.Dependency{
					{
						Name: "rake",
						Type: ":runtime",
						Requirement: &gem.Requirement{
							Requirements: []gem.RequirementConstraint{
								{Operator: ">=", Version: "12.0"},
								{Operator: "<", Version: "14.0"},
							},
						},
						Prerelease: false,
					},
				},
			},
		},
		{
			desc: "proto with nil dependency in slice",
			p: &pb.RubyGemMetadata{
				Authors: []string{"Jane Doe"},
				Dependencies: []*pb.RubyGemMetadata_Dependency{
					nil,
					{
						Name: "rake",
						Type: ":runtime",
					},
				},
			},
			want: &gem.RubyGemMetadata{
				Authors: []string{"Jane Doe"},
				Dependencies: []*gem.Dependency{
					{
						Name: "rake",
						Type: ":runtime",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := gem.ToStruct(tc.p)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("gem.ToStruct(%+v): (-want +got):\n%s", tc.p, diff)
			}
		})
	}
}

func TestMetadataRegistrationRoundTrip(t *testing.T) {
	original := &gem.RubyGemMetadata{
		Authors:     []string{"Jane Doe"},
		Description: "A gem description",
		Homepage:    "https://example.com/gem",
		Licenses:    []string{"MIT"},
		Platform:    "ruby",
		Summary:     "A short summary",
		Dependencies: []*gem.Dependency{
			{
				Name: "rake",
				Type: ":runtime",
				Requirement: &gem.Requirement{
					Requirements: []gem.RequirementConstraint{
						{Operator: ">=", Version: "12.0"},
					},
				},
				Prerelease: false,
			},
		},
	}

	anyProto, err := metadata.StructToProto(original)
	if err != nil {
		t.Fatalf("metadata.StructToProto failed: %v", err)
	}
	if anyProto == nil {
		t.Fatal("metadata.StructToProto returned nil Any proto")
	}

	decoded, err := metadata.ProtoToStruct(anyProto)
	if err != nil {
		t.Fatalf("metadata.ProtoToStruct failed: %v", err)
	}

	got, ok := decoded.(*gem.RubyGemMetadata)
	if !ok {
		t.Fatalf("metadata.ProtoToStruct returned type %T, want *gem.RubyGemMetadata", decoded)
	}

	if diff := cmp.Diff(original, got); diff != "" {
		t.Errorf("Roundtrip mismatch (-want +got):\n%s", diff)
	}
}
