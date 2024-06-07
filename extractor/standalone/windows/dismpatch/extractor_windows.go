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

//go:build windows

// Package dismpatch extract patch level from the DISM command line tool.
package dismpatch

import (
	"context"
	"os/exec"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/winproducts"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name of the extractor
	Name = "windows/dismpatch"
)

// Extractor implements the dismpatch extractor.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Extract retrieves the patch level from the DISM command line tool.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) ([]*extractor.Inventory, error) {
	output, err := runDISM(ctx)
	if err != nil {
		return nil, err
	}

	flavor := winproducts.WindowsFlavorFromRegistry()
	return inventoryFromOutput(flavor, output)
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:      purl.TypeGeneric,
		Namespace: "microsoft",
		Name:      i.Name,
		Version:   i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// runDISM executes the dism command line tool.
func runDISM(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "dism", "/online", "/get-packages", "/format:list")
	output, err := cmd.CombinedOutput()
	return string(output), err
}
