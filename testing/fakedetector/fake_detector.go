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
func (d *fakeDetector) Name() string { return d.DetName }

// Version returns the detector's version.
func (d *fakeDetector) Version() int { return d.DetVersion }

// Requirements returns the detector's requirements.
func (d *fakeDetector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// RequiredExtractors returns a list of Extractors that this Detector requires.
func (d *fakeDetector) RequiredExtractors() []string { return d.ReqExtractors }

// Scan always returns the same predefined finding or error.
func (d *fakeDetector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return d.Findings, d.Err
}

// WithName sets the fake detector's name.
func (fd *fakeDetector) WithName(name string) *fakeDetector {
	new := copier.Copy(fd).(*fakeDetector)
	new.DetName = name
	return new
}

// WithVersion sets the fake detector's version.
func (fd *fakeDetector) WithVersion(version int) *fakeDetector {
	new := copier.Copy(fd).(*fakeDetector)
	new.DetVersion = version
	return new
}

// WithRequiredExtractors sets the fake detector's required extractors.
func (fd *fakeDetector) WithRequiredExtractors(extractors ...string) *fakeDetector {
	new := copier.Copy(fd).(*fakeDetector)
	new.ReqExtractors = extractors
	return new
}

// WithPackageVuln sets the fake detector's package vulnerability that is returned when Scan() is called.
func (fd *fakeDetector) WithPackageVuln(vuln *inventory.PackageVuln) *fakeDetector {
	new := copier.Copy(fd).(*fakeDetector)
	new.Findings.PackageVulns = []*inventory.PackageVuln{vuln}
	return new
}

// WithGenericFinding sets the fake detector's generic finding that is returned when Scan() is called.
func (fd *fakeDetector) WithGenericFinding(finding *inventory.GenericFinding) *fakeDetector {
	new := copier.Copy(fd).(*fakeDetector)
	new.Findings.GenericFindings = []*inventory.GenericFinding{finding}
	return new
}

// WithErr sets the fake detector's error that is returned when Scan() is called.
func (fd *fakeDetector) WithErr(err error) *fakeDetector {
	new := copier.Copy(fd).(*fakeDetector)
	new.Err = err
	return new
}
