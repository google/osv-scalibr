// Copyright 2024 Google LLC
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

package depsjson

// Metadata holds parsing information for a deps.json package.
type Metadata struct {
	PackageName    string // The name of the package.
	PackageVersion string // The version of the package.
	// Type indicates the type of the package. Examples include:
	// - "package": Represents an external dependency, such as a NuGet package.
	// - "project": Represents an internal dependency, such as the main application
	Type string
}
