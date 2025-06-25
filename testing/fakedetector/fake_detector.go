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

// fakeDetector is an Detector implementation to be used in tests.
// It returns a predefined Finding or error.
type fakeDetector struct {
	DetName       string
	DetVersion    int
	ReqExtractors []string
	Findings      inventory.Finding
	Err           error
}

// New creates an empty new fake detector.
func New() *fakeDetector {
	return &fakeDetector{}
}

// Name returns the detector's name.
func (fd *fakeDetector) Name() string { return fd.DetName }

// Version returns the detector's version.
func (fd *fakeDetector) Version() int { return fd.DetVersion }

// Requirements returns the detector's requirements.
func (fd *fakeDetector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// RequiredExtractors returns a list of Extractors that this Detector requires.
func (fd *fakeDetector) RequiredExtractors() []string { return fd.ReqExtractors }

// Scan always returns the same predefined finding or error.
func (fd *fakeDetector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return fd.Findings, fd.Err
}

// WithName sets the fake detector's name.
func (fd *fakeDetector) WithName(name string) *fakeDetector {
	newDet := copier.Copy(fd).(*fakeDetector)
	newDet.DetName = name
	return newDet
}

// WithVersion sets the fake detector's version.
func (fd *fakeDetector) WithVersion(version int) *fakeDetector {
	newDet := copier.Copy(fd).(*fakeDetector)
	newDet.DetVersion = version
	return newDet
}

// WithRequiredExtractors sets the fake detector's required extractors.
func (fd *fakeDetector) WithRequiredExtractors(extractors ...string) *fakeDetector {
	newDet := copier.Copy(fd).(*fakeDetector)
	newDet.ReqExtractors = extractors
	return newDet
}

// WithPackageVuln sets the fake detector's package vulnerability that is returned when Scan() is called.
func (fd *fakeDetector) WithPackageVuln(vuln *inventory.PackageVuln) *fakeDetector {
	newDet := copier.Copy(fd).(*fakeDetector)
	newDet.Findings.PackageVulns = []*inventory.PackageVuln{vuln}
	return newDet
}

// WithGenericFinding sets the fake detector's generic finding that is returned when Scan() is called.
func (fd *fakeDetector) WithGenericFinding(finding *inventory.GenericFinding) *fakeDetector {
	newDet := copier.Copy(fd).(*fakeDetector)
	newDet.Findings.GenericFindings = []*inventory.GenericFinding{finding}
	return newDet
}

// WithErr sets the fake detector's error that is returned when Scan() is called.
func (fd *fakeDetector) WithErr(err error) *fakeDetector {
	newDet := copier.Copy(fd).(*fakeDetector)
	newDet.Err = err
	return newDet
}
