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
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// --- Struct to Proto

// InventoryToProto converts a Inventory go struct into the equivalent proto.
func InventoryToProto(inv *inventory.Inventory) (*spb.Inventory, error) {
	if inv == nil {
		return nil, nil
	}

	packages := make([]*spb.Package, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		p := PackageToProto(p)
		packages = append(packages, p)
	}

	// TODO(b/400910349): Add PackageVulns to the proto too.

	genericFindings := make([]*spb.GenericFinding, 0, len(inv.GenericFindings))
	for _, f := range inv.GenericFindings {
		p, err := GenericFindingToProto(f)
		if err != nil {
			return nil, err
		}
		genericFindings = append(genericFindings, p)
	}

	secrets := make([]*spb.Secret, 0, len(inv.Secrets))
	for _, s := range inv.Secrets {
		p, err := SecretToProto(s)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, p)
	}

	var containerImageMetadata []*spb.ContainerImageMetadata
	for _, cim := range inv.ContainerImageMetadata {
		containerImageMetadata = append(containerImageMetadata, containerImageMetadataToProto(cim))
	}

	return &spb.Inventory{
		Packages:               packages,
		GenericFindings:        genericFindings,
		Secrets:                secrets,
		ContainerImageMetadata: containerImageMetadata,
	}, nil
}

// --- Proto to Struct

// InventoryToStruct converts a ScanResult proto into the equivalent go struct.
func InventoryToStruct(invProto *spb.Inventory) *inventory.Inventory {
	if invProto == nil {
		return nil
	}

	var packages []*extractor.Package
	for _, pProto := range invProto.GetPackages() {
		p := PackageToStruct(pProto)
		packages = append(packages, p)
	}

	// TODO(b/400910349): Add PackageVulns to the struct too.

	var genericFindings []*inventory.GenericFinding
	for _, fProto := range invProto.GetGenericFindings() {
		f, err := GenericFindingToStruct(fProto)
		if err != nil {
			log.Errorf("Failed to convert GenericFinding to struct: %v", err)
			continue
		}
		genericFindings = append(genericFindings, f)
	}

	var secrets []*inventory.Secret
	for _, sProto := range invProto.GetSecrets() {
		s, err := SecretToStruct(sProto)
		if err != nil {
			log.Errorf("Failed to convert Secret to struct: %v", err)
			continue
		}
		secrets = append(secrets, s)
	}

	var containerImageMetadata []*extractor.ContainerImageMetadata
	for _, cimProto := range invProto.GetContainerImageMetadata() {
		cim := containerImageMetadataToStruct(cimProto)
		containerImageMetadata = append(containerImageMetadata, cim)
		for _, lm := range cim.LayerMetadata {
			lm.ParentContainer = cim
		}
	}

	for i, p := range packages {
		pProto := invProto.GetPackages()[i]
		cii := pProto.GetContainerImageMetadataIndexes()

		if cii != nil &&
			int(cii.ContainerImageIndex) < len(containerImageMetadata) {
			cim := containerImageMetadata[cii.ContainerImageIndex]
			if int(cii.LayerIndex) < len(cim.LayerMetadata) {
				p.LayerMetadata = cim.LayerMetadata[cii.LayerIndex]
			}
		}
	}

	return &inventory.Inventory{
		Packages:               packages,
		GenericFindings:        genericFindings,
		Secrets:                secrets,
		ContainerImageMetadata: containerImageMetadata,
	}
}
