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

// Package filter defines the interface to implement a unknown binary filter.
package filter

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// Filter is an interface for filtering out binaries that are known to be from an existing extracted source.
type Filter interface {
	// HashSetFilter removes binaries from the unknownBinariesSet that are found to be from a trusted source.
	HashSetFilter(ctx context.Context, fs scalibrfs.FS, unknownBinariesSet map[string]*extractor.Package) error
	// ShouldExclude returns whether a given binary path should be excluded from the scan.
	ShouldExclude(ctx context.Context, fs scalibrfs.FS, binaryPath string) bool
	// Name returns the name of the filter.
	Name() string
}
