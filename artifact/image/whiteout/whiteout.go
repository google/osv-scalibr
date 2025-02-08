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

// Package whiteout defines and implements whiteout related functions to be used in the layer
// scanning methods and functions.
package whiteout

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

const (
	// WhiteoutPrefix is the prefix found on whiteout files.
	WhiteoutPrefix = ".wh."
	// WhiteoutDirPrefix is the prefix found on whiteout directories. This means the directory cannot
	// hold any more files in the current layer, as well as future layers.
	WhiteoutDirPrefix = ".wh..wh..opq."
)

// Files outputs all of the whiteout files found in an FS.
func Files(scalibrfs scalibrfs.FS) (map[string]struct{}, error) {
	whiteouts := make(map[string]struct{})

	err := fs.WalkDir(scalibrfs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			//nolint:nilerr // continue walking if there is an error
			return nil
		}

		base := filepath.Base(path)

		if d.Type().IsRegular() && strings.HasPrefix(base, WhiteoutPrefix) {
			whiteouts[path] = struct{}{}
		}

		if d.IsDir() && strings.HasPrefix(base, WhiteoutDirPrefix) {
			whiteouts[path] = struct{}{}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to successfully walk fs to find whiteout files: %w", err)
	}
	return whiteouts, nil
}
