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

package fakefs

import (
	"errors"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// MockEvalSymlinksFS is a mock implementation of image.EvalSymlinksFS for testing.
type MockEvalSymlinksFS struct {
	scalibrfs.FS

	Symlinks map[string]string
}

// NewMockEvalSymlinksFS creates a new MockEvalSymlinksFS.
func NewMockEvalSymlinksFS(fs scalibrfs.FS, symlinks map[string]string) *MockEvalSymlinksFS {
	return &MockEvalSymlinksFS{
		FS:       fs,
		Symlinks: symlinks,
	}
}

// EvalSymlink mocks the evaluation of symlinks.
func (fs *MockEvalSymlinksFS) EvalSymlink(name string) (string, error) {
	if dest, ok := fs.Symlinks[name]; ok {
		return dest, nil
	}
	return "", errors.New("not a symlink")
}

// The following should be true, but can't be uncommented because it would cause an import cycle
// (image_test.go is in the package image, rather than image_test because it uses the private chainLayer field.)
//var _ image.EvalSymlinksFS = &MockEvalSymlinksFS{}
