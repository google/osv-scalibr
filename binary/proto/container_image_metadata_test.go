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

package proto_test

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/opencontainers/go-digest"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var d1 = digest.FromString("d1")
var d2 = digest.FromString("d2")

var cimProtoForTest = &pb.ContainerImageMetadata{
	Index: 0,
	LayerMetadata: []*pb.LayerMetadata{
		{Index: 0, DiffId: d1.String(), ChainId: d1.String(), Command: "cmd1", IsEmpty: false, BaseImageIndex: 1},
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
}

var cimStructForTest = func() *extractor.ContainerImageMetadata {
	c := &extractor.ContainerImageMetadata{
		Index: 0,
		LayerMetadata: []*extractor.LayerMetadata{
			{Index: 0, DiffID: d1, ChainID: d1, Command: "cmd1", IsEmpty: false, BaseImageIndex: 1},
			{Index: 1, DiffID: d2, ChainID: d2, Command: "cmd2", IsEmpty: true, BaseImageIndex: 0},
		},
		BaseImages: [][]*extractor.BaseImageDetails{
			{},
			{
				{Repository: "base-image", Registry: "ghcr.io", Plugin: "baseimage", ChainID: d1},
			},
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
	LayerMetadata: cimStructForTest.LayerMetadata[0],
}

var pkgWithLayerProto = &pb.Package{
	Name:    "withlayer",
	Version: "1.0",
	ContainerImageMetadataIndexes: &pb.Package_ContainerImageMetadataIndexes{
		LayerIndex:          0,
		ContainerImageIndex: 0,
	},
}
