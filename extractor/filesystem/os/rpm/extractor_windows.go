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

package rpm

import (
	"context"
	"fmt"
	"io/fs"

	extractor "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/purl"
)

// Name is the name for the RPM extractor
const Name = "os/rpm"

// Extractor extracts rpm packages from rpm database.
type Extractor struct{}

// Config contains RPM specific configuration values
type Config struct{}

// DefaultConfig returns the default configuration values for the RPM extractor.
func DefaultConfig() Config { return Config{} }

// New returns an RPM extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired always returns false as RPM extractor is not supported on Windows.
func (e Extractor) FileRequired(path string, _ fs.FileMode) bool {
	return false
}

// Extract extracts packages from rpm status files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	return nil, fmt.Errorf("Windows is not supported")
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return nil, fmt.Errorf("Windows is not supported")
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) {
	return []string{}, fmt.Errorf("Windows is not supported")
}
