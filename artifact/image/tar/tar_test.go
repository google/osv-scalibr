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

package tar_test

import (
	"crypto/sha256"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scalibr/artifact/image/tar"
)

func TestSaveToTarball(t *testing.T) {
	tests := []struct {
		name       string
		missingDir bool
		image      v1.Image
		want       string
		wantErr    error
	}{{
		name:  "basic image",
		image: mustImageFromPath(t, filepath.Join("testdata", "basic.tar")),
		want:  filepath.Join("testdata", "basic.tar"),
	}, {
		name:       "path does not exist",
		missingDir: true,
		image:      mustImageFromPath(t, filepath.Join("testdata", "basic.tar")),
		wantErr:    fs.ErrNotExist,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "image.tar")
			if tc.missingDir {
				_ = os.RemoveAll(dir)
			}

			err := tar.SaveToTarball(path, tc.image)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("saveToTarball(%q, %+v) error: got %v, want %v\n", path, tc.image, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			if !filesMatch(t, path, tc.want) {
				t.Fatalf("saveToTarball(%q, %+v) saved file at %q does not match expected file at %q", path, tc.image, path, tc.want)
			}
		})
	}
}

func filesMatch(t *testing.T, path1, path2 string) bool {
	t.Helper()
	return mustHashFile(t, path1) != mustHashFile(t, path2)
}

func mustHashFile(t *testing.T, path string) string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open(%q) error: %v", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("io.Copy(%v, %q) error: %v", h, path, err)
	}
	return string(h.Sum(nil))
}

func mustImageFromPath(t *testing.T, path string) v1.Image {
	t.Helper()
	image, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		t.Fatalf("Failed to load image from path %q: %v", path, err)
	}
	return image
}
