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

// Package binary provides functions to register additional extractors that are only
// made available in the SCALIBR CLI wrapper. This avoids pulling heavy dependencies
// (like containerd clients) into the core library.
package binary

import (
	"github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	fl "github.com/google/osv-scalibr/extractor/filesystem/list"
)

// EnableAdditionalExtractors patches the filesystem extractor lists to include containerd.
func EnableAdditionalExtractors() {
	fl.RegisterExtractor(containerd.Name, containerd.New, []string{
		"containers",
		"artifact",
	})
}
