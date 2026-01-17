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

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"

	scalibrimage "github.com/google/osv-scalibr/artifact/image"
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
func PopulateLayerDetails(ctx context.Context, inv *inventory.Inventory, chainLayers []scalibrimage.ChainLayer, extractors []filesystem.Extractor, config *filesystem.Config) {
	// If there are no chain layers, then there is nothing to trace. This should not happen, but we
	// should handle it gracefully.
	if len(chainLayers) == 0 {
		log.Warnf("No chain layers found, cannot trace inventory.")
		return
	}

	cim := &extractor.ContainerImageMetadata{
		Index: len(inv.ContainerImageMetadata),
	}
	inv.ContainerImageMetadata = append(inv.ContainerImageMetadata, cim)
	fillLayerMetadataFromChainLayers(cim, chainLayers)

	osInfo, err := osrelease.GetOSRelease(chainLayers[len(chainLayers)-1].FS())
	if err == nil {
		cim.OSInfo = osInfo
	}

	// Helper function to update the extractor config.
	updateExtractorConfig := func(pathsToExtract []string, extractor filesystem.Extractor, chainFS scalibrfs.FS) {
		config.Extractors = []filesystem.Extractor{extractor}
		config.PathsToExtract = pathsToExtract
		config.ScanRoots = []*scalibrfs.ScanRoot{
			&scalibrfs.ScanRoot{
				FS: chainFS,
			},
		}
	}

	// locationIndexToPackages is used as a package cache to avoid re-extracting the same
	// package from a file multiple times.
	locationIndexToPackages := map[locationAndIndex][]*extractor.Package{}
	lastLayerIndex := len(chainLayers) - 1

	// Build a map from the extractor list for faster access.
	nameToExtractor := map[string]filesystem.Extractor{}
	for _, e := range extractors {
		nameToExtractor[e.Name()] = e
	}

	for _, pkg := range inv.Packages {
		layerDetails := cim.LayerMetadata[lastLayerIndex]
		var pkgExtractor filesystem.Extractor
		for _, name := range pkg.Plugins {
			if ex, ok := nameToExtractor[name]; ok {
				pkgExtractor = ex
				break
			}
		}

		// If the package has no locations or no filesystem Extractor, it cannot be traced.
		isPackageTraceable := pkgExtractor != nil && len(pkg.Locations) > 0
		if !isPackageTraceable {
			continue
		}

		var pkgPURL string
		if pkg.PURL() != nil {
			pkgPURL = pkg.PURL().String()
		}

		var foundOrigin bool
		fileLocation := pkg.Locations[0]
		lastScannedLayerIndex := len(chainLayers) - 1

		// Go backwards through the chain layers and find the first layer where the package is not
		// present. Such layer is the layer in which the package was introduced. If the package is
		// present in all layers, then it means it was introduced in the first layer.
		for i := len(chainLayers) - 2; i >= 0; i-- {
			oldChainLayer := chainLayers[i]

			pkgLocationAndIndex := locationAndIndex{
				location: fileLocation,
				index:    i,
			}

			var oldPackages []*extractor.Package
			if cachedPackages, ok := locationIndexToPackages[pkgLocationAndIndex]; ok {
				oldPackages = cachedPackages
			} else if _, err := oldChainLayer.FS().Stat(fileLocation); errors.Is(err, fs.ErrNotExist) {
				// Check if file still exist in this layer, if not skip extraction.
				// This is both an optimization, and avoids polluting the log output with false file not found errors.
				oldPackages = []*extractor.Package{}
			} else if filesExistInLayer(oldChainLayer, pkg.Locations) {
				// Update the extractor config to use the files from the current layer.
				// We only take extract the first location because other locations are derived from the initial
				// extraction location. If other locations can no longer be determined from the first location
				// they should not be included here, and the trace for those packages stops here.
				updateExtractorConfig([]string{fileLocation}, pkgExtractor, oldChainLayer.FS())

				// Runs SCALIBR extraction on the file of interest in oldChainLayer.
				oldInv, _, err := filesystem.Run(ctx, config)
				oldPackages = oldInv.Packages
				if err != nil {
					break
				}
			} else {
				// If none of the files from the packages are present in the underlying layer, then there
				// will be no difference in the extracted packages from oldChainLayer, so extraction can be
				// skipped in the chain layer. This is an optimization to avoid extracting the same package
				// multiple times.
				continue
			}

			// Cache the packages for future use.
			locationIndexToPackages[pkgLocationAndIndex] = oldPackages

			foundPackage := false
			for _, oldPKG := range oldPackages {
				// PURLs are being used as a package key, so if they are different, skip this package.
				oldPKGPURL := oldPKG.PURL()
				if oldPKGPURL == nil || oldPKGPURL.String() != pkgPURL {
					continue
				}

				if !areLocationsEqual(oldPKG.Locations, pkg.Locations) {
					continue
				}

				foundPackage = true
				break
			}

			// If the package is not present in the old layer, then it was introduced in the previous layer we actually scanned
			if !foundPackage {
				layerDetails = cim.LayerMetadata[lastScannedLayerIndex]
				foundOrigin = true
				break
			}

			// This is now the latest scanned layer
			lastScannedLayerIndex = i
		}

		// If the package is present in every layer, then it means it was introduced in the first
		// layer.
		if !foundOrigin {
			layerDetails = cim.LayerMetadata[0]
		}
		pkg.LayerMetadata = layerDetails
	}
}

// areLocationsEqual checks if the package location strings are equal.
func areLocationsEqual(fileLocations []string, otherFileLocations []string) bool {
	if len(fileLocations) == 0 || len(otherFileLocations) == 0 {
		log.Warnf("Empty file locations found. This should not happen.")
		return false
	}

	return fileLocations[0] == otherFileLocations[0]
}

// getSingleLayerFSFromChainLayer returns the filesystem of the underlying layer in the chain layer.
func getLayerFSFromChainLayer(chainLayer scalibrimage.ChainLayer) (scalibrfs.FS, error) {
	layer := chainLayer.Layer()
	if layer == nil {
		return nil, errors.New("chain layer has no layer")
	}

	fs := layer.FS()
	if fs == nil {
		return nil, errors.New("layer has no filesystem")
	}

	return fs, nil
}

func fillLayerMetadataFromChainLayers(cim *extractor.ContainerImageMetadata, chainLayers []scalibrimage.ChainLayer) {
	// Create list of layer details struct to be referenced by inventory.
	for i, chainLayer := range chainLayers {
		// Get the string representation of the diffID, and remove the algorithm prefix if it exists.
		// TODO: b/406537132 - Determine if diffIDs should be validated via the Validate function in
		// golang/opencontainers/digest/algorithm.go. Just getting the string representation of the
		// diffID acts as failing open, but perhaps we should consider validating the diffID and logging
		// a warning if it isn't.
		metadata := &extractor.LayerMetadata{
			Index:           i,
			ParentContainer: cim,
			ChainID:         chainLayer.ChainID(),
			DiffID:          chainLayer.Layer().DiffID(),
			Command:         chainLayer.Layer().Command(),
			IsEmpty:         chainLayer.Layer().IsEmpty(),
		}
		cim.LayerMetadata = append(cim.LayerMetadata, metadata)
	}
}

// filesExistInLayer checks if any of the provided files are present in the underlying layer of the
// chain layer.
func filesExistInLayer(chainLayer scalibrimage.ChainLayer, fileLocations []string) bool {
	layerFS, err := getLayerFSFromChainLayer(chainLayer)
	if err != nil {
		return false
	}

	// Check if any of the files are present in the underlying layer.
	for _, fileLocation := range fileLocations {
		if _, err := layerFS.Stat(fileLocation); err == nil {
			return true
		}
	}
	return false
}
