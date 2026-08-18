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

// Metadata holds setup.cfg-specific package metadata for future enrichment.
type Metadata struct {
	// Requirement is the full PEP 508 requirement string (e.g. "requests==2.31.0").
	Requirement string
	// VersionComparator is the operator used (e.g. "==", ">=", "~=").
	VersionComparator string
	// DepGroupVals holds the extras group (e.g. "dev", "test") if this
	// dependency came from [options.extras_require].
	DepGroupVals []string
}

// IsProtoable marks this metadata as not proto-serialized yet.
func (m *Metadata) IsProtoable() {}
