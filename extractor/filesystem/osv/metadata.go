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

package osv

// Metadata holds parsing information for packages extracted by an OSV extractor wrapper.
type Metadata struct {
	PURLType  string
	Commit    string
	Ecosystem string
	CompareAs string
}

// DepGroups provides access to the dependency groups property in some metadata objects
type DepGroups interface {
	DepGroups() []string
}

// osv.DepGroupMetadata is a metadata struct that only supports DepGroups
type DepGroupMetadata struct {
	DepGroupVals []string
}

var _ DepGroups = DepGroupMetadata{}

// DepGroups return the dependency groups property in the metadata
func (dgm DepGroupMetadata) DepGroups() []string {
	return dgm.DepGroupVals
}

// DistroVersionMetadata contains distro versions
// This is not meant to be used directly. The distro version should be retrieved
// from the Ecosystem() function.
type DistroVersionMetadata struct {
	DistroVersionStr string
}
