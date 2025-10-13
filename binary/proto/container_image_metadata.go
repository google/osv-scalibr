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

package proto

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/log"
	"github.com/opencontainers/go-digest"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func layerMetadataToProto(lm *extractor.LayerMetadata) *spb.LayerMetadata {
	if lm == nil {
		return nil
	}
	return &spb.LayerMetadata{
		Index:          int32(lm.Index),
		DiffId:         lm.DiffID.String(),
		ChainId:        lm.ChainID.String(),
		Command:        lm.Command,
		IsEmpty:        lm.IsEmpty,
		BaseImageIndex: int32(lm.BaseImageIndex),
	}
}

func baseImageDetailsToProto(bid *extractor.BaseImageDetails) *spb.BaseImageDetails {
	if bid == nil {
		return nil
	}
	return &spb.BaseImageDetails{
		Repository: bid.Repository,
		Registry:   bid.Registry,
		Plugin:     bid.Plugin,
	}
}

func containerImageMetadataToProto(cim *extractor.ContainerImageMetadata) *spb.ContainerImageMetadata {
	if cim == nil {
		return nil
	}
	var layerMetadata []*spb.LayerMetadata
	for _, lm := range cim.LayerMetadata {
		layerMetadata = append(layerMetadata, layerMetadataToProto(lm))
	}

	baseImageChains := []*spb.BaseImageChain{
		// The first base image is always empty.
		&spb.BaseImageChain{},
	}

	if len(cim.BaseImages) > 1 {
		for _, bi := range cim.BaseImages[1:] {
			var baseImageDetails []*spb.BaseImageDetails
			for _, bid := range bi {
				baseImageDetails = append(baseImageDetails, baseImageDetailsToProto(bid))
			}
			if len(bi) == 0 {
				// This should never happen
				continue
			}

			baseImageChains = append(baseImageChains, &spb.BaseImageChain{
				BaseImages: baseImageDetails,
				ChainId:    bi[0].ChainID.String(),
			})
		}
	}

	return &spb.ContainerImageMetadata{
		Index:           int32(cim.Index),
		OsInfo:          cim.OSInfo,
		LayerMetadata:   layerMetadata,
		BaseImageChains: baseImageChains,
	}
}

func layerMetadataToStruct(lm *spb.LayerMetadata) *extractor.LayerMetadata {
	if lm == nil {
		return nil
	}
	diffID, err := digest.Parse(lm.GetDiffId())
	if err != nil {
		log.Errorf("Failed to parse diff ID %q: %v", lm.GetDiffId(), err)
	}
	chainID, err := digest.Parse(lm.GetChainId())
	if err != nil {
		log.Errorf("Failed to parse chain ID %q: %v", lm.GetChainId(), err)
	}
	return &extractor.LayerMetadata{
		Index:          int(lm.GetIndex()),
		DiffID:         diffID,
		ChainID:        chainID,
		Command:        lm.GetCommand(),
		IsEmpty:        lm.GetIsEmpty(),
		BaseImageIndex: int(lm.GetBaseImageIndex()),
	}
}

func baseImageDetailsToStruct(bid *spb.BaseImageDetails, chainID digest.Digest) *extractor.BaseImageDetails {
	if bid == nil {
		return nil
	}

	return &extractor.BaseImageDetails{
		Repository: bid.GetRepository(),
		Registry:   bid.GetRegistry(),
		Plugin:     bid.GetPlugin(),
		ChainID:    chainID,
	}
}

func containerImageMetadataToStruct(cim *spb.ContainerImageMetadata) *extractor.ContainerImageMetadata {
	if cim == nil {
		return nil
	}
	var layerMetadata []*extractor.LayerMetadata
	for _, lm := range cim.GetLayerMetadata() {
		layerMetadata = append(layerMetadata, layerMetadataToStruct(lm))
	}
	baseImages := [][]*extractor.BaseImageDetails{
		// The first base image is always empty.
		[]*extractor.BaseImageDetails{},
	}
	baseImageChains := cim.GetBaseImageChains()
	if len(baseImageChains) > 1 {
		for _, bic := range baseImageChains[1:] {
			chainID, err := digest.Parse(bic.GetChainId())
			if err != nil {
				log.Errorf("Failed to parse chain ID %q: %v", bic.GetChainId(), err)
				continue
			}

			var baseImageDetails []*extractor.BaseImageDetails
			for _, bid := range bic.GetBaseImages() {
				baseImageDetails = append(baseImageDetails, baseImageDetailsToStruct(bid, chainID))
			}
			baseImages = append(baseImages, baseImageDetails)
		}
	}

	return &extractor.ContainerImageMetadata{
		Index:         int(cim.GetIndex()),
		OSInfo:        cim.GetOsInfo(),
		LayerMetadata: layerMetadata,
		BaseImages:    baseImages,
	}
}
