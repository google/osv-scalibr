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

// Package mongodbatlasapikey extends the veles mongodbatlasapikey.Detector to search inside
// MongoDB Atlas CLI configuration files (~/.config/atlascli/config.toml and ~/.config/mongocli/config.toml).
package mongodbatlasapikey

import (
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	"github.com/google/osv-scalibr/veles/secrets/mongodbatlasapikey"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the name of the extractor.
	Name = "secrets/mongodbatlasapikey"
	// Version is the version of the extractor.
	Version = 0
)

// New returns a filesystem.Extractor which extracts MongoDB Atlas API keys
// using the mongodbatlasapikey.Detector.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return convert.FromVelesDetectorWithRequire(
		mongodbatlasapikey.NewDetector(), Name, Version, FileRequired,
	), nil
}

// FileRequired returns true if the file is a MongoDB Atlas or mongocli configuration file.
func FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	return strings.HasSuffix(path, ".config/atlascli/config.toml") ||
		strings.HasSuffix(path, ".config/mongocli/config.toml")
}
