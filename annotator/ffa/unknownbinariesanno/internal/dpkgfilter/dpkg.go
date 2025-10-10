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

// Package dpkgfilter filters out binaries that are part of a dpkg package
package dpkgfilter

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/filter"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/common/linux/dpkg"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

var (
	ignorePathPrefix = []string{
		// We want to ignore everything in the info directory as DPKG indexes doesn't index itself.
		// There are many executable scripts in this directory, including preinstall/postinstall/preremove/postremove scripts.
		"var/lib/dpkg/info",
		// This is a debian docker specific file to disable irrelevant services from starting during apt install
		"usr/sbin/policy-rc.d",
	}
)

// DpkgFilter is a filter for binaries that are part of a dpkg package.
type DpkgFilter struct{}

var _ filter.Filter = DpkgFilter{}

// Name returns the name of the filter.
func (DpkgFilter) Name() string {
	return "DpkgFilter"
}

// HashSetFilter removes binaries from the input set that are found in dpkg .list files.
func (DpkgFilter) HashSetFilter(ctx context.Context, fs scalibrfs.FS, unknownBinariesSet map[string]*extractor.Package) error {
	it, err := dpkg.NewListFilePathIterator(fs)
	if err != nil {
		return err
	}
	defer it.Close()

	var errs []error
	for {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}

		filePath, err := it.Next(ctx)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				errs = append(errs, err)
			}
			break
		}

		// Remove leading '/' since SCALIBR fs paths don't include that.
		// noop if filePath doesn't exist
		delete(unknownBinariesSet, strings.TrimPrefix(filePath, "/"))

		if evalFS, ok := fs.(image.EvalSymlinksFS); ok {
			evalPath, err := evalFS.EvalSymlink(filePath)
			if err != nil {
				continue
			}
			delete(unknownBinariesSet, strings.TrimPrefix(evalPath, "/"))
		}
	}

	return errors.Join(errs...)
}

// ShouldExclude returns whether a given binary path should be excluded from the scan.
func (d DpkgFilter) ShouldExclude(_ context.Context, _ scalibrfs.FS, binaryPath string) bool {
	for _, ignorePath := range ignorePathPrefix {
		if strings.HasPrefix(binaryPath, ignorePath) {
			return true
		}
	}

	return false
}
