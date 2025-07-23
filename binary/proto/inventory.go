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

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// --- Struct to Proto

// InventoryToProto converts a Inventory go struct into the equivalent proto.
func InventoryToProto(inv *inventory.Inventory) (*spb.Inventory, error) {
	packages := make([]*spb.Package, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		p := packageToProto(p)
		packages = append(packages, p)
	}

	// TODO(b/400910349): Add PackageVulns to the proto too.

	genericFindings := make([]*spb.GenericFinding, 0, len(inv.GenericFindings))
	for _, f := range inv.GenericFindings {
		p, err := genericFindingToProto(f)
		if err != nil {
			return nil, err
		}
		genericFindings = append(genericFindings, p)
	}

	secrets := make([]*spb.Secret, 0, len(inv.Secrets))
	for _, s := range inv.Secrets {
		p, err := secretToProto(s)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, p)
	}

	return &spb.Inventory{
		Packages:        packages,
		GenericFindings: genericFindings,
		Secrets:         secrets,
	}, nil
}

// --- Proto to Struct

// InventoryToStruct converts a ScanResult proto into the equivalent go struct.
func InventoryToStruct(invProto *spb.Inventory) *inventory.Inventory {
	var packages []*extractor.Package
	for _, pProto := range invProto.GetPackages() {
		p := packageToStruct(pProto)
		packages = append(packages, p)
	}
	// TODO - b/421456154: implement conversion or remaining types.

	return &inventory.Inventory{
		Packages: packages,
	}
}
