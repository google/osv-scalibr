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

// Package fakeextractor provides a Extractor implementation to be used in tests.
package fakeextractor

import (
	"context"
	"errors"
	"io/fs"

	scalibrextractor "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/purl"
)

// NamesErr is a list of Inventory names and an error.
type NamesErr struct {
	Names []string
	Err   error
}

// extractor is an Extractor implementation to be used in tests.
type extractor struct {
	name           string
	version        int
	requiredFiles  map[string]bool
	pathToNamesErr map[string]NamesErr
}

// New returns a fake extractor.
//
// The extractor returns FileRequired(path) = true for any path in requiredFiles.
// The extractor returns the inventory and error from pathToNamesErr given the same path to Extract(...).
func New(name string, version int, requiredFiles []string, pathToNamesErr map[string]NamesErr) scalibrextractor.InventoryExtractor {

	rfs := map[string]bool{}
	for _, path := range requiredFiles {
		rfs[path] = true
	}

	// Maintain non-nil fields to avoid nil pointers on access such as FileRequired(...).
	if len(pathToNamesErr) == 0 {
		pathToNamesErr = map[string]NamesErr{}
	}

	return &extractor{
		name:           name,
		version:        version,
		requiredFiles:  rfs,
		pathToNamesErr: pathToNamesErr,
	}
}

// Name returns the extractor's name.
func (e *extractor) Name() string { return e.name }

// Version returns the extractor's version.
func (e *extractor) Version() int { return e.version }

// FileRequired should return true if the file described by path and mode is
// relevant for the extractor.
//
// FileRequired returns true if the path was in requiredFiles and its value is true during
// construction in New(..., requiredFiles, ...) and false otherwise.
func (e *extractor) FileRequired(path string, mode fs.FileMode) bool {
	return e.requiredFiles[path]
}

// Extract extracts inventory data relevant for the extractor from a given file.
//
// Extract returns the inventory list and error associated with input.Path from the pathToInventoryErr map used
// during construction in NewExtractor(..., pathToInventoryErr, ...).
func (e *extractor) Extract(ctx context.Context, input *scalibrextractor.ScanInput) ([]*scalibrextractor.Inventory, error) {

	namesErr, ok := e.pathToNamesErr[input.Path]
	if !ok {
		return nil, errors.New("unrecognized path")
	}

	invs := []*scalibrextractor.Inventory{}
	for _, name := range namesErr.Names {
		invs = append(invs, &scalibrextractor.Inventory{
			Name:      name,
			Locations: []string{input.Path},
		})
	}

	return invs, namesErr.Err
}

// ToPURL returns a fake PURL based on the inventory name+version.
func (e *extractor) ToPURL(i *scalibrextractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs always returns an empty array.
func (e *extractor) ToCPEs(i *scalibrextractor.Inventory) ([]string, error) { return []string{}, nil }
