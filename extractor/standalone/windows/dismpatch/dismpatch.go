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

package dismpatch

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/winproducts"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch/dismparser"
	"github.com/google/osv-scalibr/purl"
)

// inventoryFromOutput parses the output of DISM and produces inventory entries from it.
func inventoryFromOutput(flavor, output string) ([]*extractor.Inventory, error) {
	packages, imgVersion, err := dismparser.Parse(output)
	if err != nil {
		return nil, err
	}

	imgVersion = strings.TrimSpace(imgVersion)
	windowsProduct := winproducts.WindowsProductFromVersion(flavor, imgVersion)
	inventory := []*extractor.Inventory{
		{
			Name:    windowsProduct,
			Version: imgVersion,
			Metadata: &metadata.OSVersion{
				Product:     windowsProduct,
				FullVersion: imgVersion,
			},
		},
	}

	// extract KB informations
	for _, pkg := range packages {
		inventory = append(inventory, &extractor.Inventory{
			Name:    pkg.PackageIdentity,
			Version: pkg.PackageVersion,
		})
	}

	return inventory, nil
}

// Ecosystem returns no ecosystem since OSV does ont support dism patches yet.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "" }

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	p := &purl.PackageURL{
		Type:      purl.TypeGeneric,
		Namespace: "microsoft",
		Name:      i.Name,
	}

	switch meta := i.Metadata.(type) {
	case *metadata.OSVersion:
		p.Qualifiers = purl.QualifiersFromMap(map[string]string{
			purl.BuildNumber: meta.FullVersion,
		})
	default:
		p.Version = i.Version
	}

	return p
}
