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

package filter

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
)

// AttributePackage marks a package found in unknownBinariesSet as belonging to the local filesystem
// by adding attribution in the package's metadata
func AttributePackage(unknownBinariesSet map[string]*extractor.Package, path string) {
	pkg, ok := unknownBinariesSet[strings.TrimPrefix(path, "/")]
	if !ok {
		return
	}

	md, ok := pkg.Metadata.(*unknownbinariesextr.UnknownBinaryMetadata)
	if !ok {
		return
	}

	md.Attribution.LocalFilesystem = true
}
