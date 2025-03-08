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

// Package pypi defines the structures to parse PyPI JSON API response.
package pypi

// Response defines the response of PyPI JSON API.
type Response struct {
	Info     Info     `json:"info"`
	Releases Releases `json:"releases"`
}

// Info holds the info in the response of PyPI JSON API.
type Info struct {
	RequiresDist []string `json:"requires_dist"`
}

// Release is a map of version to its release information.
type Releases map[string][]Release

// Release holds the information about a release.
type Release struct {
	Digests Digests `json:"digests"`
}

// Digests holds the information of digests of a release.
type Digests struct {
	SHA256 string `json:"sha256"`
}
