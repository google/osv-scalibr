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

// Package awsaccesskey extends the veles awsaccesskey.Detector to search inside the `~/.aws/credentials` file
package awsaccesskey

import (
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/veles/secrets/awsaccesskey"

	"github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
)

const (
	// Name is the name of the extractor
	Name = "secrets/awsaccesskey"
	// Version is the version of the extractor
	Version = 0
)

// New returns a filesystem.Extractor which extracts AWS Access Keys using the awsaccesskey.Detector
func New() filesystem.Extractor {
	return convert.FromVelesDetectorWithRequire(
		awsaccesskey.NewDetector(), Name, Version, FileRequired,
	)
}

// FileRequired returns true if a file contains aws credentials.
func FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	return strings.HasSuffix(path, ".aws/credentials")
}
