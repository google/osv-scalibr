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
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

// inventoryFromOutput parses the output of DISM and produces package entries from it.
func inventoryFromOutput(flavor, output string) (inventory.Inventory, error) {
	packages, imgVersion, err := dismparser.Parse(output)
	if err != nil {
		return inventory.Inventory{}, err
	}

	imgVersion = strings.TrimSpace(imgVersion)
	windowsProduct := winproducts.WindowsProductFromVersion(flavor, imgVersion)
	result := []*extractor.Package{
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
		result = append(result, &extractor.Package{
			Name:    pkg.PackageIdentity,
			Version: pkg.PackageVersion,
		})
	}

	return inventory.Inventory{Packages: result}, nil
}

// Ecosystem returns no ecosystem since OSV does ont support dism patches yet.
func (Extractor) Ecosystem(p *extractor.Package) string { return "" }

// ToPURL converts a package created by this extractor into a PURL.
func (e Extractor) ToPURL(pkg *extractor.Package) *purl.PackageURL {
	p := &purl.PackageURL{
		Type:      purl.TypeGeneric,
		Namespace: "microsoft",
		Name:      pkg.Name,
	}

	switch meta := pkg.Metadata.(type) {
	case *metadata.OSVersion:
		p.Qualifiers = purl.QualifiersFromMap(map[string]string{
			purl.BuildNumber: meta.FullVersion,
		})
	default:
		p.Version = pkg.Version
	}

	return p
}
