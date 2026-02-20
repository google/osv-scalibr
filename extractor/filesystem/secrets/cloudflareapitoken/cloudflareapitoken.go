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

// Package cloudflareapitoken extends the veles cloudflareapitoken.Detector to search inside
// Cloudflare-specific configuration files
package cloudflareapitoken

import (
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	"github.com/google/osv-scalibr/veles/secrets/cloudflareapitoken"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the name of the extractor
	Name = "secrets/cloudflareapitoken"
	// Version is the version of the extractor
	Version = 0
)

// FileRequired reports whether the plugin should scan the given file.
// It restricts scanning to paths that contain "cloudflare" in the path or filename.
func FileRequired(api filesystem.FileAPI) bool {
	path := strings.ToLower(api.Path())
	return strings.Contains(path, "cloudflare")
}

// New returns a filesystem.Extractor which extracts Cloudflare API Tokens using the cloudflareapitoken.Detector
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return convert.FromVelesDetectorWithRequire(
		cloudflareapitoken.NewDetector(), Name, Version, FileRequired,
	), nil
}
