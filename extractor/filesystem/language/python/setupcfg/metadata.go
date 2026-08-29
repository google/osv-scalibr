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

package setupcfg

import (
	"github.com/google/osv-scalibr/binary/proto/metadata"
)

func init() {
	// setup.cfg dependency metadata is intentionally not serialized to a
	// dedicated proto yet; it is preserved in-memory for extraction and tests.
	metadata.RegisterNil[*Metadata]()
}

// Metadata contains additional information about a package parsed from a
// setup.cfg dependency entry.
type Metadata struct {
	// VersionComparator is the comparator used in the requirement spec, e.g.
	// "==", ">=", "~=". Empty when no comparator was present.
	VersionComparator string
	// DepGroup is the [options.extras_require] group the entry belongs to.
	// Empty for entries from [options] install_requires.
	DepGroup string
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}
