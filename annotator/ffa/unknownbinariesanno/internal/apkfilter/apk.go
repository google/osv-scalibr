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

// Package apkfilter filters out binaries that are part of an apk package.
package apkfilter

import (
	"context"
	"path"
	"strings"

	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/filter"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk/apkutil"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

var (
	apkDBPath = "lib/apk/db/installed"

	ignorePathPrefix = []string{
		// We want to ignore everything in the apk db directory as APK indexes doesn't index itself.
		"lib/apk/db",
	}
)

// ApkFilter is a filter for binaries that are part of an apk package.
type ApkFilter struct{}

var _ filter.Filter = ApkFilter{}

// Name returns the name of the filter.
func (ApkFilter) Name() string {
	return "ApkFilter"
}

// HashSetFilter removes binaries from the input set that are found in the apk database.
func (ApkFilter) HashSetFilter(ctx context.Context, fs scalibrfs.FS, unknownBinariesSet map[string]*extractor.Package) error {
	reader, err := fs.Open(apkDBPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	s := apkutil.NewScanner(reader)
	for s.Scan() {
		var currentDir string
		for _, kv := range s.FullRecord() {
			switch kv.Key {
			case "F":
				currentDir = kv.Value
			case "R":
				if currentDir == "" {
					continue
				}
				filePath := path.Join(currentDir, kv.Value)
				delete(unknownBinariesSet, filePath)

				if evalFS, ok := fs.(image.EvalSymlinksFS); ok {
					// EvalSymlink expects an absolute path from the root of the image.
					evalPath, err := evalFS.EvalSymlink("/" + filePath)
					if err != nil {
						continue
					}
					delete(unknownBinariesSet, strings.TrimPrefix(evalPath, "/"))
				}
			}
		}
	}
	return s.Err()
}

// ShouldExclude returns whether a given binary path should be excluded from the scan.
func (d ApkFilter) ShouldExclude(_ context.Context, _ scalibrfs.FS, binaryPath string) bool {
	for _, ignorePath := range ignorePathPrefix {
		if strings.HasPrefix(binaryPath, ignorePath) {
			return true
		}
	}

	return false
}
