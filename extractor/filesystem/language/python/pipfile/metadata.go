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

package pipfile

// Metadata holds additional information about a package extracted from a Pipfile.
type Metadata struct {
	// DepGroupVals contains the dependency group(s) this package belongs to,
	// e.g. ["dev"] for dev-only packages or [] for production packages.
	DepGroupVals []string
	// Requirement is the pip-compatible requirement string constructed from the
	// package name and its version spec, e.g. "requests==2.31.0" or "flask".
	// This is stored so future enrichers can perform transitive dependency
	// resolution (analogous to requirements.Metadata.Requirement).
	Requirement string
	// VersionComparator is the operator used in the version spec, e.g. "==",
	// ">=", "~=". Empty when the spec is a bare version, a wildcard, or an
	// unsupported compound constraint.
	VersionComparator string
}

// IsProtoable marks Metadata as a protoable metadata type.
func (m *Metadata) IsProtoable() {}
