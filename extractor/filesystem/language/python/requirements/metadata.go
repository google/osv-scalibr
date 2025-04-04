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

package requirements

// Metadata contains additional information from a package in a requirements file.
type Metadata struct {
	// The values from the --hash flags, as in https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode.
	// These are the hashes of the distributions of the package.
	HashCheckingModeValues []string
	// The comparator used to compare the package version, e.g. ==, ~=, >=
	VersionComparator string
	// The dependency requirement to used for dependency resolution
	Requirement string
}
