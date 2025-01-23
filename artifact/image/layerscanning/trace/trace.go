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

// Package trace provides functionality to trace the origin of an inventory in a container image.
package trace

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"sort"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"

	scalibrImage "github.com/google/osv-scalibr/artifact/image"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// locationAndIndex is a struct to represent a location and the index of the layer it was found in.
type locationAndIndex struct {
	location string
	index    int
}

// PopulateLayerDetails populates the LayerDetails field of the inventory with the origin details
// obtained by tracing the inventory in the image.
//
// It does this by looking at each consecutive pair (n, n+1) of chain layers in reverse order and
// checking if a package is present in layer n+1, but not layer n. For example, consider the chain
// layers, each with a different set of packages:
//
//	Chain Layer 0: Packages A, B
//	Chain Layer 1: Packages A
//	Chain Layer 2: Packages A, B, C
//
// Then the origin of package C is layer 2, because it is not present in layer 1, but it is in
// layer 2. Even though package B is present in layer 0, it is attributed to layer 2 because it
// exists in layer 2, but not in layer 1. Package A is attributed to layer 0 because it is present
// in all layers.
//
// Note that a precondition of this algorithm is that the chain layers are ordered by order of
// creation.
func PopulateLayerDetails(ctx context.Context, inventory []*extractor.Inventory, chainLayers []scalibrImage.ChainLayer, config *filesystem.Config) {
	chainLayerDetailsList := []*extractor.LayerDetails{}

	// Create list of layer details struct to be referenced by inventory.
	for i, chainLayer := range chainLayers {
		var diffID string
		if chainLayer.Layer().IsEmpty() {
			diffID = ""
		} else {
			diffID = chainLayer.Layer().DiffID().Encoded()
		}

		chainLayerDetailsList = append(chainLayerDetailsList, &extractor.LayerDetails{
			Index:       i,
			DiffID:      diffID,
			Command:     chainLayer.Layer().Command(),
			InBaseImage: false,
		})
	}

	// Helper function to update the extractor config.
	updateExtractorConfig := func(filesToExtract []string, extractor filesystem.Extractor, chainFS scalibrfs.FS) {
		config.Extractors = []filesystem.Extractor{extractor}
		config.FilesToExtract = filesToExtract
		config.ScanRoots = []*scalibrfs.ScanRoot{
			&scalibrfs.ScanRoot{
				FS: chainFS,
			},
		}
	}

	// locationIndexToInventory is used as an inventory cache to avoid re-extracting the same
	// inventory from a file multiple times.
	locationIndexToInventory := map[locationAndIndex][]*extractor.Inventory{}
	lastLayerIndex := len(chainLayers) - 1

	for _, inv := range inventory {
		layerDetails := chainLayerDetailsList[lastLayerIndex]
		invExtractor, isFilesystemExtractor := inv.Extractor.(filesystem.Extractor)

		// Only filesystem extractors are supported for layer scanning. Also, if the inventory has no
		// locations, it cannot be traced.
		isInventoryTraceable := isFilesystemExtractor && len(inv.Locations) > 0
		if !isInventoryTraceable {
			continue
		}

		var foundOrigin bool

		// Go backwards through the chain layers and find the first layer where the inventory is not
		// present. Such layer is the layer in which the inventory was introduced. If the inventory is
		// present in all layers, then it means it was introduced in the first layer.
		// TODO: b/381249869 - Optimization: Skip layers if file not found.
		for i := len(chainLayers) - 2; i >= 0; i-- {
			oldChainLayer := chainLayers[i]

			invLocationAndIndex := locationAndIndex{
				location: inv.Locations[0],
				index:    i,
			}

			var oldInventory []*extractor.Inventory
			if cachedInventory, ok := locationIndexToInventory[invLocationAndIndex]; ok {
				oldInventory = cachedInventory
			} else {
				// Check if file still exist in this layer, if not skip extraction.
				// This is both an optimization, and avoids polluting the log output with false file not found errors.
				if _, err := oldChainLayer.FS().Stat(inv.Locations[0]); errors.Is(err, fs.ErrNotExist) {
					oldInventory = []*extractor.Inventory{}
				} else {
					// Update the extractor config to use the files from the current layer.
					// We only take extract the first location because other locations are derived from the initial
					// extraction location. If other locations can no longer be determined from the first location
					// they should not be included here, and the trace for those packages stops here.
					updateExtractorConfig([]string{inv.Locations[0]}, invExtractor, oldChainLayer.FS())

					var err error
					oldInventory, _, err = filesystem.Run(ctx, config)
					if err != nil {
						break
					}
				}

				// Cache the inventory for future use.
				locationIndexToInventory[invLocationAndIndex] = oldInventory
			}

			foundPackage := false
			for _, oldInv := range oldInventory {
				if areInventoriesEqual(inv, oldInv) {
					foundPackage = true
					break
				}
			}

			// If the inventory is not present in the old layer, then it was introduced in layer i+1.
			if !foundPackage {
				layerDetails = chainLayerDetailsList[i+1]
				foundOrigin = true
				break
			}
		}

		// If the inventory is present in every layer, then it means it was introduced in the first
		// layer.
		if !foundOrigin {
			layerDetails = chainLayerDetailsList[0]
		}
		inv.LayerDetails = layerDetails
	}
}

// areInventoriesEqual checks if two inventories are equal. It does this by comparing the PURLs and
// the locations of the inventories.
func areInventoriesEqual(inv1 *extractor.Inventory, inv2 *extractor.Inventory) bool {
	if inv1.Extractor == nil || inv2.Extractor == nil {
		return false
	}

	// Check if the PURLs are equal.
	purl1 := inv1.Extractor.ToPURL(inv1)
	purl2 := inv2.Extractor.ToPURL(inv2)

	if purl1.String() != purl2.String() {
		return false
	}

	// Check if the locations are equal.
	locations1 := inv1.Locations[:]
	sort.Strings(locations1)

	locations2 := inv2.Locations[:]
	sort.Strings(locations2)

	if !slices.Equal(locations1, locations2) {
		return false
	}
	return true
}
