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

// JSONResponse defines the response of JSON API.
// https://docs.pypi.org/api/json/
type JSONResponse struct {
	Info Info  `json:"info"`
	URLs []URL `json:"urls"`
}

// Info holds the info in the response of PyPI JSON API.
type Info struct {
	RequiresDist []string `json:"requires_dist"`
	Yanked       bool     `json:"yanked"`
}

// URL holds the information about a release.
type URL struct {
	Digests Digests `json:"digests"`
}

// Digests holds the information of digests of a release.
type Digests struct {
	SHA256 string `json:"sha256"`
}

// IndexReponse defines the response of Index API.
// https://docs.pypi.org/api/index-api/
type IndexReponse struct {
	Versions []string `json:"versions"`
}
