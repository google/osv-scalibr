// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Package annotator add Annotation to inventories
// TODO(b/400910349): Migrate into a separate plugin type
package annotator

import (
	"github.com/google/osv-scalibr/extractor"
)

// Annotate adds annotations to the packages
func Annotate(pkgs []*extractor.Package) {
	for _, pkg := range pkgs {
		for _, loc := range pkg.Locations {
			if IsInsideCacheDir(loc) {
				pkg.Annotations = append(pkg.Annotations, extractor.InsideCacheDir)
			}
		}
	}
}
