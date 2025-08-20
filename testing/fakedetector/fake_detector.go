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

// Package fakedetector provides a Detector implementation to be used in tests.
package fakedetector

import (
	"context"

	"github.com/google/go-cpy/cpy"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

var (
	copier = cpy.New(
		cpy.IgnoreAllUnexported(),
	)
)

// FakeDetector is a Detector implementation to be used in tests.
// It returns a predefined Finding or error.
type FakeDetector struct {
	DetName       string
	DetVersion    int
	ReqExtractors []string
	Findings      inventory.Finding
	Err           error
}

// New creates an empty new fake detector.
func New() *FakeDetector {
	return &FakeDetector{}
}

// Name returns the detector's name.
func (fd *FakeDetector) Name() string { return fd.DetName }

// Version returns the detector's version.
func (fd *FakeDetector) Version() int { return fd.DetVersion }

// Requirements returns the detector's requirements.
func (fd *FakeDetector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// RequiredExtractors returns a list of Extractors that this Detector requires.
func (fd *FakeDetector) RequiredExtractors() []string { return fd.ReqExtractors }

// DetectedFinding returns generic vulnerability information about what is detected.
func (fd *FakeDetector) DetectedFinding() inventory.Finding {
	return inventory.Finding{}
}

// Scan always returns the same predefined finding or error.
func (fd *FakeDetector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return fd.Findings, fd.Err
}

// WithName sets the fake detector's name.
func (fd *FakeDetector) WithName(name string) *FakeDetector {
	newDet := copier.Copy(fd).(*FakeDetector)
	newDet.DetName = name
	return newDet
}

// WithVersion sets the fake detector's version.
func (fd *FakeDetector) WithVersion(version int) *FakeDetector {
	newDet := copier.Copy(fd).(*FakeDetector)
	newDet.DetVersion = version
	return newDet
}

// WithRequiredExtractors sets the fake detector's required extractors.
func (fd *FakeDetector) WithRequiredExtractors(extractors ...string) *FakeDetector {
	newDet := copier.Copy(fd).(*FakeDetector)
	newDet.ReqExtractors = extractors
	return newDet
}

// WithPackageVuln sets the fake detector's package vulnerability that is returned when Scan() is called.
func (fd *FakeDetector) WithPackageVuln(vuln *inventory.PackageVuln) *FakeDetector {
	newDet := copier.Copy(fd).(*FakeDetector)
	newDet.Findings.PackageVulns = []*inventory.PackageVuln{vuln}
	return newDet
}

// WithGenericFinding sets the fake detector's generic finding that is returned when Scan() is called.
func (fd *FakeDetector) WithGenericFinding(finding *inventory.GenericFinding) *FakeDetector {
	newDet := copier.Copy(fd).(*FakeDetector)
	newDet.Findings.GenericFindings = []*inventory.GenericFinding{finding}
	return newDet
}

// WithErr sets the fake detector's error that is returned when Scan() is called.
func (fd *FakeDetector) WithErr(err error) *FakeDetector {
	newDet := copier.Copy(fd).(*FakeDetector)
	newDet.Err = err
	return newDet
}
