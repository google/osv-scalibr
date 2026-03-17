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

// Package gitlabrunnerconfig extends the veles gitlab.RunnerAuthTokenDetector to search inside
// GitLab Runner configuration files
package gitlabrunnerconfig

import (
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the name of the extractor
	Name = "secrets/gitlabrunnerconfig"
	// Version is the version of the extractor
	Version = 0
)

// FileRequired reports whether the plugin should scan the given file.
// It restricts scanning to files named config.toml in paths containing "gitlab-runner"
func FileRequired(api filesystem.FileAPI) bool {
	path := strings.ToLower(api.Path())
	filename := filepath.Base(path)
	return filename == "config.toml" && strings.Contains(path, "gitlab-runner")
}

// New returns a filesystem.Extractor which extracts GitLab Runner authentication tokens using the gitlab.RunnerAuthTokenDetector
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return convert.FromVelesDetectorWithRequire(
		gitlab.NewRunnerAuthTokenDetector(), Name, Version, FileRequired,
	), nil
}
