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

// Package metadata defines a Metadata struct for PE version resource packages.
package metadata

// Metadata holds PE version resource information for a Windows executable or DLL.
type Metadata struct {
	// OriginalPath is the path where the PE file was found.
	OriginalPath string
	// RawVersion is the unprocessed version string from PE resources.
	RawVersion string
	// CompanyName from PE version resources.
	CompanyName string
	// FileDescription from PE version resources.
	FileDescription string
	// OriginalFilename from PE version resources.
	OriginalFilename string
	// InternalName from PE version resources.
	InternalName string
	// PrivateBuild from PE version resources.
	PrivateBuild string
	// SpecialBuild from PE version resources.
	SpecialBuild string
	// Comments from PE version resources.
	Comments string
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}
