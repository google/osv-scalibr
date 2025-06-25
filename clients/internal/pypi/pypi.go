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

// IndexResponse defines the response of Index API.
// https://docs.pypi.org/api/index-api/
type IndexResponse struct {
	Name     string   `json:"name"`
	Files    []File   `json:"files"`
	Versions []string `json:"versions"`
}

// File holds the information of a file in index response.
type File struct {
	Name   string `json:"filename"`
	URL    string `json:"url"`
	Yanked Yanked `json:"yanked"`
}

// Yanked represents the yanked field in the index response.
// This can either be false or a string representing the yanked reason.
type Yanked struct {
	Value bool
}

// UnmarshalJSON implements the json.Unmarshaler interface for BoolOrString
func (y *Yanked) UnmarshalJSON(data []byte) error {
	// Try unmarshalling as a boolean
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		y.Value = b
		return nil
	}

	// If unmarshalling as a boolean fails, try unmarshalling as a string
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		// We don't really need the yanked reason, just need to know it's yanked.
		y.Value = true
		return nil
	}

	// If both fail, return an error
	return fmt.Errorf("could not unmarshal %s as yanked", string(data))
}
