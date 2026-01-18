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
	"fmt"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// PackageVulnToProto converts a PackageVuln struct to proto.
func PackageVulnToProto(v *inventory.PackageVuln, pkgToID map[*extractor.Package]string) (*spb.PackageVuln, error) {
	if v == nil {
		return nil, nil
	}

	var pkgID string
	var ok bool
	if v.Package != nil {
		pkgID, ok = pkgToID[v.Package]
		if !ok {
			return nil, fmt.Errorf("%v package %q version %q not found in pkgToID map", v.Package.Ecosystem().String(), v.Package.Name, v.Package.Version)
		}
	}

	var exps []*spb.FindingExploitabilitySignal
	for _, exp := range v.ExploitabilitySignals {
		expProto := FindingVEXToProto(exp)
		exps = append(exps, expProto)
	}

	return &spb.PackageVuln{
		Vuln:                  v.Vulnerability,
		PackageId:             pkgID,
		Plugins:               v.Plugins,
		ExploitabilitySignals: exps,
	}, nil
}

// PackageVulnToStruct converts a PackageVuln proto into the equivalent go struct.
func PackageVulnToStruct(v *spb.PackageVuln, idToPkg map[string]*extractor.Package) (*inventory.PackageVuln, error) {
	if v == nil {
		return nil, nil
	}

	if v.GetPackageId() == "" {
		return nil, fmt.Errorf("package ID is empty for PackageVuln %+v", v)
	}

	pkg, ok := idToPkg[v.GetPackageId()]
	if !ok {
		return nil, fmt.Errorf("package with ID %q not found in idToPkg map", v.GetPackageId())
	}

	var exps []*vex.FindingExploitabilitySignal
	for _, exp := range v.GetExploitabilitySignals() {
		expStruct := FindingVEXToStruct(exp)
		exps = append(exps, expStruct)
	}

	return &inventory.PackageVuln{
		Vulnerability:         v.GetVuln(),
		Package:               pkg,
		Plugins:               v.GetPlugins(),
		ExploitabilitySignals: exps,
	}, nil
}
