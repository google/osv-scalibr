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

// Package convert provides a utility function for converting Veles plugins
// (Detectors and Validators) to SCALIBR core plugins (FilesystemExtractors and Enrichers)
package convert

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/extractor/filesystem"
	sf "github.com/google/osv-scalibr/extractor/filesystem/secrets"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles"
)

// FromVelesDetector converts a Veles Detector into a SCALIBR FilesystemExtractor plugin.
// This allows enabling Veles Detectors individually like regular SCALIBR plugins.
// The wrapped FilesystemExtractor does not do any extraction on its own - it's a placeholder plugin
// that is used to configure the Veles detection before the scan starts.
func FromVelesDetector(velesDetector veles.Detector, name string, version int) func() filesystem.Extractor {
	return func() filesystem.Extractor {
		return &detectorWrapper{velesDetector: velesDetector, name: name, version: version}
	}
}

// detectorWrapper is a wrapper around the veles.Detector interface that
// implements the additional functions of the filesystem Extractor interface.
type detectorWrapper struct {
	velesDetector veles.Detector
	name          string
	version       int
}

// MaxSecretLen returns the maximum length a secret from this Detector can have.
func (d *detectorWrapper) MaxSecretLen() uint32 {
	return d.velesDetector.MaxSecretLen()
}

// Detect finds candidate secrets in the data and returns them alongside their
// starting positions.
func (d *detectorWrapper) Detect(data []byte) ([]veles.Secret, []int) {
	return d.velesDetector.Detect(data)
}

// Name of the secret extractor.
func (d *detectorWrapper) Name() string {
	return d.name
}

// Version of the secret extractor.
func (d *detectorWrapper) Version() int {
	return d.version
}

// Requirements of the secret extractor.
func (d *detectorWrapper) Requirements() *plugin.Capabilities {
	// Veles plugins don't have any special requirements.
	return &plugin.Capabilities{}
}

// FileRequired is a dummy function to satisfy the interface requirements.
// It always returns false since wrapped secret scanner plugins all run through the
// central veles FilesystemExtractor plugin.
func (d *detectorWrapper) FileRequired(api filesystem.FileAPI) bool {
	return false
}

// Extract is a dummy function to satisfy the interface requirements.
// It always returns an error since wrapped secret scanner plugins all run through the
// central veles FilesystemExtractor plugin.
func (d *detectorWrapper) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, errors.New("Extract not implemented - Plugin should run through the central Veles detection engine")
}

// Assert that detectorWrapper implements the required interfaces.
var _ veles.Detector = &detectorWrapper{}
var _ filesystem.Extractor = &detectorWrapper{}

// SetupVelesExtractors configures the central Veles secret detection plugin using the placeholder
// plugins found in the extractor list. Returns the updated extractor list.
func SetupVelesExtractors(extractors []filesystem.Extractor) ([]filesystem.Extractor, error) {
	result := make([]filesystem.Extractor, 0, len(extractors))
	detectors := []veles.Detector{}
	for _, e := range extractors {
		if d, ok := e.(veles.Detector); ok {
			detectors = append(detectors, d)
		} else {
			result = append(result, e)
		}
	}

	// Add the veles extractor with the configured detectors.
	if len(detectors) != 0 {
		engine, err := veles.NewDetectionEngine(detectors)
		if err != nil {
			return nil, err
		}
		result = append(result, sf.NewWithEngine(engine))
	}

	return result, nil
}
