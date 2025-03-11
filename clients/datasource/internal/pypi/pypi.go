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

import (
	"encoding/json"
	"fmt"
)

// JsonResponse defines the response of JSON API.
// https://docs.pypi.org/api/json/
type JsonResponse struct {
	Info Info `json:"info"`
}

// Info holds the info in the response of PyPI JSON API.
type Info struct {
	RequiresDist []string `json:"requires_dist"`
}

// IndexReponse defines the response of Index API.
// https://docs.pypi.org/api/index-api/
type IndexReponse struct {
	Files    []File   `json:"files"`
	Versions []string `json:"versions"`
}

// File has the information of a file in Index API.
type File struct {
	Hashes Hashes       `json:"hashes"`
	Yanked BoolOrString `json:"yanked"`
}

// Hashes holds the information of digests of a release.
type Hashes struct {
	SHA256 string `json:"sha256"`
}

type BoolOrString struct {
	Value interface{} // Can hold either bool or string
}

func (bos *BoolOrString) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		bos.Value = b
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		bos.Value = s
		return nil
	}

	return fmt.Errorf("could not unmarshal %s into bool or string", data)
}
