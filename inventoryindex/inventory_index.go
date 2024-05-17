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

// Package inventoryindex is a wrapper around the collected inventory, which
// provides methods for fast lookup of identified software.
package inventoryindex

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
)

// InventoryIndex allows you to query the inventory result.
type InventoryIndex struct {
	// Two-dimensional map: package type -> (package name -> Inventory).
	invMap map[string]map[string][]*extractor.Inventory
}

// New creates an InventoryIndex based on the specified extraction results.
func New(inv []*extractor.Inventory) (*InventoryIndex, error) {
	invMap := make(map[string]map[string][]*extractor.Inventory)
	for _, i := range inv {
		p, err := toPURL(i)
		if err != nil {
			return nil, err
		}
		if p == nil {
			continue
		}
		if _, ok := invMap[p.Type]; !ok {
			invMap[p.Type] = make(map[string][]*extractor.Inventory)
		}
		invMap[p.Type][p.Name] = append(invMap[p.Type][p.Name], i)
	}
	return &InventoryIndex{invMap: invMap}, nil
}

// GetAll lists all detected software inventory.
func (ix *InventoryIndex) GetAll() []*extractor.Inventory {
	result := []*extractor.Inventory{}
	for _, m := range ix.invMap {
		for _, i := range m {
			result = append(result, i...)
		}
	}
	return result
}

// GetAllOfType lists all detected software inventory of a given purl
// package type (e.g. "deb" "golang" "pypi").
func (ix *InventoryIndex) GetAllOfType(packageType string) []*extractor.Inventory {
	result := []*extractor.Inventory{}
	m, ok := ix.invMap[packageType]
	if !ok {
		return result
	}
	for _, i := range m {
		result = append(result, i...)
	}
	return result
}

// GetSpecific lists all versions of a software with the specified name+package type.
func (ix *InventoryIndex) GetSpecific(name string, packageType string) []*extractor.Inventory {
	result := []*extractor.Inventory{}
	m, ok := ix.invMap[packageType]
	if !ok {
		return result
	}
	i, ok := m[name]
	if !ok {
		return result
	}
	return i
}

func toPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return i.Extractor.ToPURL(i)
}
