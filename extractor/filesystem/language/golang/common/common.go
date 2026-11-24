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

// Package common provides shared helpers for Go extractors.
package common

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	golangmeta "github.com/google/osv-scalibr/extractor/filesystem/language/golang/metadata"
	"golang.org/x/mod/modfile"
)

const devel = "(devel)"

// IsRemoteReplacement checks if a module replace target points to another remote Go module.
func IsRemoteReplacement(path, version string) bool {
	return path != "" && !modfile.IsDirectoryPath(path) && version != "" && version != devel
}

// ApplyReplacement mutates pkg in place to apply a Go module replace directive.
func ApplyReplacement(pkg *extractor.Package, replacePath, replaceVersion string) {
	switch {
	case replacePath == "":
		// No replacement, nothing to do.
	case IsRemoteReplacement(replacePath, replaceVersion):
		pkg.Name = replacePath
		pkg.Version = strings.TrimPrefix(replaceVersion, "v")
	default:
		// Local replacement, store the path as metadata.
		pkg.Metadata = &golangmeta.Metadata{LocalReplacePath: replacePath}
	}
}
