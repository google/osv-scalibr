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

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
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
	var c *detector.Finding
	if finding != nil {
		c = &detector.Finding{}
		*c = *finding
	}
	return &fakeDetector{
		DetName:    name,
		DetVersion: version,
		Finding:    c,
		Err:        err,
	}
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
func (d *fakeDetector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) ([]*detector.Finding, error) {
	if d.Finding == nil {
		return nil, d.Err
	}
	return []*detector.Finding{d.Finding}, d.Err
}

// Option is an option that can be set when creating a new fake detector
type Option func(*fakeDetector)

// WithName sets the fake detector's name.
func WithName(name string) Option {
	return func(fd *fakeDetector) {
		fd.DetName = name
	}
}

// WithVersion sets the fake detector's version.
func WithVersion(version int) Option {
	return func(fd *fakeDetector) {
		fd.DetVersion = version
	}
}

// WithRequiredExtractors sets the fake detector's required extractors.
func WithRequiredExtractors(extractors ...string) Option {
	return func(fd *fakeDetector) {
		fd.ReqExtractors = extractors
	}
}

// WithFinding sets the fake detector's finding that is returned when Scan() is called.
func WithFinding(finding *detector.Finding) Option {
	return func(fd *fakeDetector) {
		fd.Finding = finding
	}
}

// WithErr sets the fake detector's error that is returned when Scan() is called.
func WithErr(err error) Option {
	return func(fd *fakeDetector) {
		fd.Err = err
	}
}

// NewWithOptions creates a new fake detector with its properties set according to opts.
func NewWithOptions(opts ...Option) detector.Detector {
	fd := &fakeDetector{}
	for _, opt := range opts {
		opt(fd)
	}
	return fd
}
