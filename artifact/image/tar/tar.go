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

// Package tar provides functionality for saving a container image to a tarball.
package tar

import (
	"fmt"
	"io"
	"os"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/osv-scalibr/log"
)

// SaveToTarball saves a container image to a tarball.
func SaveToTarball(path string, image v1.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create tar file %q: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close tar file %q: %v", path, err)
		}
	}()

	r := mutate.Extract(image)
	defer r.Close()

	if _, err := io.Copy(f, r); err != nil {
		if strings.Contains(err.Error(), "invalid tar header") {
			return fmt.Errorf("failed to copy image tar to %q: %w", path, err)
		}
		return fmt.Errorf("failed to copy image tar to %q: %w", path, err)
	}

	return nil
}
