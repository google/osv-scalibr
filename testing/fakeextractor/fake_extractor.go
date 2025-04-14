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

// Package fakeextractor provides a Extractor implementation to be used in tests.
package fakeextractor

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// NamesErr is a list of Package names and an error.
type NamesErr struct {
	Names []string
	Err   error
}

// fakeExtractor is an Extractor implementation to be used in tests.
type fakeExtractor struct {
	name           string
	version        int
	requiredFiles  map[string]bool
	pathToNamesErr map[string]NamesErr
}

// AllowUnexported is a utility function to be used with cmp.Diff to
// compare structs that contain the fake extractor.
var AllowUnexported = cmp.AllowUnexported(fakeExtractor{})

// New returns a fake fakeExtractor.
//
// The fakeExtractor returns FileRequired(path) = true for any path in requiredFiles.
// The fakeExtractor returns the package and error from pathToNamesErr given the same path to Extract(...).
func New(name string, version int, requiredFiles []string, pathToNamesErr map[string]NamesErr) filesystem.Extractor {
	rfs := map[string]bool{}
	for _, path := range requiredFiles {
		rfs[path] = true
	}

	// Maintain non-nil fields to avoid nil pointers on access such as FileRequired(...).
	if len(pathToNamesErr) == 0 {
		pathToNamesErr = map[string]NamesErr{}
	}

	return &fakeExtractor{
		name:           name,
		version:        version,
		requiredFiles:  rfs,
		pathToNamesErr: pathToNamesErr,
	}
}

// Name returns the extractor's name.
func (e *fakeExtractor) Name() string { return e.name }

// Version returns the extractor's version.
func (e *fakeExtractor) Version() int { return e.version }

// Requirements returns the extractor's requirements.
func (e *fakeExtractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired should return true if the file described by path and mode is
// relevant for the extractor.
//
// FileRequired returns true if the path was in requiredFiles and its value is true during
// construction in New(..., requiredFiles, ...) and false otherwise.
// Note: because mapfs forces all paths to slash, we have to align with it here.
func (e *fakeExtractor) FileRequired(api filesystem.FileAPI) bool {
	return e.requiredFiles[filepath.ToSlash(api.Path())]
}

// Extract extracts package data relevant for the extractor from a given file.
//
// Extract returns the package list and error associated with input.Path from the pathToPackageErr map used
// during construction in NewExtractor(..., pathToPackageErr, ...).
// Note: because mapfs forces all paths to slash, we have to align with it here.
func (e *fakeExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	path := filepath.ToSlash(input.Path)
	namesErr, ok := e.pathToNamesErr[path]
	if !ok {
		return inventory.Inventory{}, errors.New("unrecognized path")
	}

	pkgs := []*extractor.Package{}
	for _, name := range namesErr.Names {
		pkgs = append(pkgs, &extractor.Package{
			Name:      name,
			Locations: []string{path},
		})
	}

	return inventory.Inventory{Packages: pkgs}, namesErr.Err
}

// ToPURL returns a fake PURL based on the package name+version.
func (e *fakeExtractor) ToPURL(p *extractor.Package) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    p.Name,
		Version: p.Version,
	}
}

// Ecosystem returns a fake ecosystem.
func (e *fakeExtractor) Ecosystem(p *extractor.Package) string {
	return "FakeEcosystem"
}
