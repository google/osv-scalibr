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

package proto_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/binary/proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/opencontainers/go-digest"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var d1 = digest.FromString("d1")
var d2 = digest.FromString("d2")

var cimProtoForTest = &pb.ContainerImageMetadata{
	Index: 0,
	LayerMetadata: []*pb.LayerMetadata{
		{
			Index:          0,
			DiffId:         d1.String(),
			ChainId:        d1.String(),
			Command:        "cmd1",
			IsEmpty:        false,
			BaseImageIndex: 1,
			Attributes: []*pb.LayerAttribute{
				{Value: "nice-layer", Plugin: "fake/layermetadataextractor"},
			},
		},
		{Index: 1, DiffId: d2.String(), ChainId: d2.String(), Command: "cmd2", IsEmpty: true, BaseImageIndex: 0},
	},
	BaseImageChains: []*pb.BaseImageChain{
		{},
		{
			ChainId: d1.String(),
			BaseImages: []*pb.BaseImageDetails{
				{Repository: "base-image", Registry: "ghcr.io", Plugin: "baseimage"},
			},
		},
	},
	Labels: map[string]string{
		"label1": "value1",
		"label2": "value2",
	},
}

var cimStructForTest = func() *extractor.ContainerImageMetadata {
	c := &extractor.ContainerImageMetadata{
		Index: 0,
		LayerMetadata: []*extractor.LayerMetadata{
			{
				Index:          0,
				DiffID:         d1,
				ChainID:        d1,
				Command:        "cmd1",
				IsEmpty:        false,
				BaseImageIndex: 1,
				Attributes: []*extractor.LayerAttribute{
					{Value: "nice-layer", Plugin: "fake/layermetadataextractor"},
				},
			},
			{Index: 1, DiffID: d2, ChainID: d2, Command: "cmd2", IsEmpty: true, BaseImageIndex: 0},
		},
		BaseImages: [][]*extractor.BaseImageDetails{
			{},
			{
				{Repository: "base-image", Registry: "ghcr.io", Plugin: "baseimage", ChainID: d1},
			},
		},
		Labels: map[string]string{
			"label1": "value1",
			"label2": "value2",
		},
	}
	for _, lm := range c.LayerMetadata {
		lm.ParentContainer = c
	}
	return c
}()

var pkgWithLayerStruct = &extractor.Package{
	Name:          "withlayer",
	Version:       "1.0",
	Location:      extractor.LocationFromPath("/file1"),
	LayerMetadata: cimStructForTest.LayerMetadata[0],
}

var pkgWithLayerProto = &pb.Package{
	Name:     "withlayer",
	Version:  "1.0",
	Location: pkgLocProtoFromPath("/file1"),
	ContainerImageMetadataIndexes: &pb.Package_ContainerImageMetadataIndexes{
		LayerIndex:          0,
		ContainerImageIndex: 0,
	},
}

func TestContainerImageMetadataBaseImageChains(t *testing.T) {
	t.Run("picks_first_non_empty_chain_id_and_skips_nil_entries", func(t *testing.T) {
		inv := &inventory.Inventory{
			ContainerImageMetadata: []*extractor.ContainerImageMetadata{
				{
					Index: 0,
					LayerMetadata: []*extractor.LayerMetadata{
						{Index: 0, DiffID: d1, ChainID: d1, BaseImageIndex: 1},
					},
					BaseImages: [][]*extractor.BaseImageDetails{
						{},
						{
							nil,
							{Repository: "buildpacks-base", Registry: "gcr.io", Plugin: "buildpacks", ChainID: ""},
							{Repository: "nginx", Registry: "docker.io", Plugin: "baseimage", ChainID: d1},
						},
					},
				},
			},
		}

		gotProto, err := proto.InventoryToProto(inv)
		if err != nil {
			t.Fatalf("InventoryToProto() unexpected error: %v", err)
		}
		wantChains := []*pb.BaseImageChain{
			{},
			{
				ChainId: d1.String(),
				BaseImages: []*pb.BaseImageDetails{
					{Repository: "buildpacks-base", Registry: "gcr.io", Plugin: "buildpacks"},
					{Repository: "nginx", Registry: "docker.io", Plugin: "baseimage"},
				},
			},
		}
		if diff := cmp.Diff(wantChains, gotProto.GetContainerImageMetadata()[0].GetBaseImageChains(), protocmp.Transform()); diff != "" {
			t.Errorf("BaseImageChains diff (-want +got):\n%s", diff)
		}

		gotStruct := proto.InventoryToStruct(gotProto)
		wantBaseImages := [][]*extractor.BaseImageDetails{
			{},
			{
				{Repository: "buildpacks-base", Registry: "gcr.io", Plugin: "buildpacks", ChainID: d1},
				{Repository: "nginx", Registry: "docker.io", Plugin: "baseimage", ChainID: d1},
			},
		}
		if diff := cmp.Diff(wantBaseImages, gotStruct.ContainerImageMetadata[0].BaseImages); diff != "" {
			t.Errorf("round-tripped BaseImages diff (-want +got):\n%s", diff)
		}
	})

	t.Run("empty_or_invalid_chain_id_does_not_drop_chains_or_shift_indices", func(t *testing.T) {
		invProto := &pb.Inventory{
			ContainerImageMetadata: []*pb.ContainerImageMetadata{
				{
					Index: 0,
					LayerMetadata: []*pb.LayerMetadata{
						{Index: 0, DiffId: d1.String(), ChainId: d1.String(), BaseImageIndex: 2},
						{Index: 1, DiffId: d2.String(), ChainId: d2.String(), BaseImageIndex: 1},
					},
					BaseImageChains: []*pb.BaseImageChain{
						{},
						{
							ChainId: "",
							BaseImages: []*pb.BaseImageDetails{
								{Repository: "offline-base", Registry: "gcr.io", Plugin: "buildpacks"},
							},
						},
						{
							ChainId: d1.String(),
							BaseImages: []*pb.BaseImageDetails{
								{Repository: "alpine", Registry: "docker.io", Plugin: "baseimage"},
							},
						},
						{
							ChainId: "not-a-valid-digest",
							BaseImages: []*pb.BaseImageDetails{
								nil,
								{Repository: "invalid-digest-base", Registry: "gcr.io", Plugin: "other"},
							},
						},
					},
				},
			},
		}

		gotStruct := proto.InventoryToStruct(invProto)
		cim := gotStruct.ContainerImageMetadata[0]
		wantBaseImages := [][]*extractor.BaseImageDetails{
			{},
			{
				{Repository: "offline-base", Registry: "gcr.io", Plugin: "buildpacks", ChainID: ""},
			},
			{
				{Repository: "alpine", Registry: "docker.io", Plugin: "baseimage", ChainID: d1},
			},
			{
				{Repository: "invalid-digest-base", Registry: "gcr.io", Plugin: "other", ChainID: ""},
			},
		}
		if diff := cmp.Diff(wantBaseImages, cim.BaseImages, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("InventoryToStruct() BaseImages diff (-want +got):\n%s", diff)
		}
		if cim.LayerMetadata[0].BaseImageIndex != 2 || cim.LayerMetadata[1].BaseImageIndex != 1 {
			t.Errorf("LayerMetadata BaseImageIndex values = [%d, %d], want [2, 1]",
				cim.LayerMetadata[0].BaseImageIndex, cim.LayerMetadata[1].BaseImageIndex)
		}

		// Re-serializing preserves chain indices even when BaseImages[1] has an empty ChainID.
		reProto, err := proto.InventoryToProto(gotStruct)
		if err != nil {
			t.Fatalf("InventoryToProto() unexpected error: %v", err)
		}
		wantReProtoChains := []*pb.BaseImageChain{
			{},
			{
				BaseImages: []*pb.BaseImageDetails{
					{Repository: "offline-base", Registry: "gcr.io", Plugin: "buildpacks"},
				},
			},
			{
				ChainId: d1.String(),
				BaseImages: []*pb.BaseImageDetails{
					{Repository: "alpine", Registry: "docker.io", Plugin: "baseimage"},
				},
			},
			{
				BaseImages: []*pb.BaseImageDetails{
					{Repository: "invalid-digest-base", Registry: "gcr.io", Plugin: "other"},
				},
			},
		}
		if diff := cmp.Diff(wantReProtoChains, reProto.GetContainerImageMetadata()[0].GetBaseImageChains(), protocmp.Transform()); diff != "" {
			t.Errorf("round-tripped BaseImageChains diff (-want +got):\n%s", diff)
		}
	})
}
