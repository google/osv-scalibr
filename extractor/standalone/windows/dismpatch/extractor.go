// Copyright 2024 Google LLC
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
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/winproducts"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch/dismparser"
)

// inventoryFromOutput parses the output of DISM and produces inventory entries from it.
func inventoryFromOutput(flavor, output string) ([]*extractor.Inventory, error) {
	packages, imgVersion, err := dismparser.Parse(string(output))
	if err != nil {
		return nil, err
	}

	imgVersion = strings.TrimSpace(imgVersion)
	windowsProduct := winproducts.WindowsProductFromVersion(flavor, imgVersion)
	inventory := []*extractor.Inventory{
		&extractor.Inventory{
			Name:      windowsProduct,
			Version:   imgVersion,
			Locations: []string{"cmd-dism-osver"},
		},
	}

	// extract KB informations
	for _, pkg := range packages {
		inventory = append(inventory, &extractor.Inventory{
			Name:      pkg.PackageIdentity,
			Version:   pkg.PackageVersion,
			Locations: []string{"cmd-dism"},
		})
	}

	return inventory, nil
}
