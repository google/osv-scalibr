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

// Package fakedetector provides a Detector implementation to be used in tests.
package fakedetector

import (
	"context"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/inventoryindex"
)

// fakeDetector is an Detector implementation to be used in tests.
// It returns a predefined Finding or error.
type fakeDetector struct {
	DetName       string
	DetVersion    int
	ReqExtractors []string
	Finding       *detector.Finding
	Err           error
}

// New returns a fake detector.
//
// The detector returns the specified Finding or error.
func New(name string, version int, finding *detector.Finding, err error) detector.Detector {
	var copy *detector.Finding
	if finding != nil {
		copy = &detector.Finding{}
		*copy = *finding
	}
	return &fakeDetector{
		DetName:    name,
		DetVersion: version,
		Finding:    copy,
		Err:        err,
	}
}

// Name returns the detector's name.
func (d *fakeDetector) Name() string { return d.DetName }

// Version returns the detector's version.
func (d *fakeDetector) Version() int { return d.DetVersion }

// RequiredExtractors returns a list of Extractors that this Detector requires.
func (d *fakeDetector) RequiredExtractors() []string { return d.ReqExtractors }

// Scan always returns the same predefined finding or error.
func (d *fakeDetector) Scan(ctx context.Context, scanRoot string, ix *inventoryindex.InventoryIndex) ([]*detector.Finding, error) {
	if d.Finding == nil {
		return nil, d.Err
	}
	return []*detector.Finding{d.Finding}, d.Err
}
