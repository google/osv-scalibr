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

// Package codecommit extends the veles codecommit.Detector to search inside the git config and history files
package codecommit

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/gitbasicauth"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/codecommit"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the name of the extractor
	Name = "secrets/codecommitcredentials"
	// Version is the version of the extractor
	Version = 0
)

// New returns a filesystem.Extractor which extracts CodeCommit Credentials using the codecommit.Detector
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return convert.FromVelesDetectorWithRequire(
		codecommit.NewDetector(), Name, Version, gitbasicauth.FileRequired,
	), nil
}
