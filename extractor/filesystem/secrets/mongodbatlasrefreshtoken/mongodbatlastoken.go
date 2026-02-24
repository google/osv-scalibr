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

// Package mongodbatlasrefreshtoken extends the veles mongodbatlasrefreshtoken.Detector to search inside
// MongoDB Atlas CLI configuration files
package mongodbatlasrefreshtoken

import (
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	"github.com/google/osv-scalibr/veles/secrets/mongodbatlasrefreshtoken"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the name of the extractor
	Name = "secrets/mongodbatlasrefreshtoken"
	// Version is the version of the extractor
	Version = 0
)

// FileRequired reports whether the plugin should scan the given file.
// It restricts scanning to the MongoDB Atlas CLI config file.
func FileRequired(api filesystem.FileAPI) bool {
	path := strings.ToLower(api.Path())
	return strings.HasSuffix(path, "atlascli/config.toml")
}

// New returns a filesystem.Extractor which extracts MongoDB Atlas Access Tokens using the mongodbatlarefreshtoken.Detector
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return convert.FromVelesDetectorWithRequire(
		mongodbatlasrefreshtoken.NewDetector(), Name, Version, FileRequired,
	), nil
}
