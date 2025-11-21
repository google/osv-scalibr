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

// Package awscredentials extracts credentials from the .aws/credentials file
package awscredentials

import (
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/awsaccesskey"
	"github.com/google/osv-scalibr/veles/secrets/gcshmackey"
)

// New returns a new extractor which searches for credentials in the .aws/credentials file
func New() filesystem.Extractor {
	return convert.FromVelesDetectorWithRequire(
		[]veles.Detector{awsaccesskey.NewDetector(), gcshmackey.NewDetector()},
		"secrets/awscredentials",
		0,
		func(api filesystem.FileAPI) bool {
			path := filepath.ToSlash(api.Path())
			return strings.HasSuffix(path, ".aws/credentials")
		},
	)
}
