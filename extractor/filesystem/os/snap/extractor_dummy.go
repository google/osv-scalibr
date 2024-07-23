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

//go:build !linux

package snap

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

// Name is the unique name of this extractor.
const Name = "os/snap"

// Extractor extracts snap apps.
type Extractor struct{}

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config { return Config{} }

// New returns a SNAP extractor.
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

// FileRequired returns true if the specified file matches snap.yaml file pattern.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	return false
}

// Extract extracts snap info from snap.yaml file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	return nil, fmt.Errorf("not supported")
}

// ToPURL is not applicable for SNAP as is not a part of the PURL spec.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return nil, fmt.Errorf("not supported")
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) {
	return []string{}, fmt.Errorf("not supported")
}
