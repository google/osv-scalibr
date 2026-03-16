// Copyright 2026 Google LLC
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

// Package fakefs provides a fake file system implementation for testing.
package fakefs

import (
	"io/fs"
	"strings"
	"testing/fstest"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"golang.org/x/tools/txtar"
)

// FileModifier allows mutating a file (e.g., compressing data, changing mode)
type FileModifier func(name string, f *fstest.MapFile) error

// PrepareFS parses a txtar string into a mock filesystem.
// Optional modifiers can be provided to intercept and modify files (e.g., compression).
// Files ending in "/" in the txtar archive are treated as empty directories.
func PrepareFS(txt string, modifiers ...FileModifier) (scalibrfs.FS, error) {
	archive := txtar.Parse([]byte(txt))
	mfs := make(fstest.MapFS)

	for _, tf := range archive.Files {
		// If it ends in /, it's a directory.
		if cut, ok := strings.CutSuffix(tf.Name, "/"); ok {
			mfs[cut] = &fstest.MapFile{Mode: fs.ModeDir | 0755}
			continue
		}

		mf := &fstest.MapFile{
			Data: tf.Data,
			Mode: 0644,
		}

		for _, mod := range modifiers {
			if err := mod(tf.Name, mf); err != nil {
				return nil, err
			}
		}

		mfs[tf.Name] = mf
	}

	return mfs, nil
}
