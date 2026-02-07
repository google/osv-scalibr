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

package cratesioapitoken

import (
	"encoding/json"
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	randomCrateName = "osvscalibr361aa9c83e8d69e1"
	randomUserName  = "velesvalidationtestuser"
	// We need to use a random crate name that is unlikely to exist.
	endpointURL = "https://crates.io/api/v1/crates/" + randomCrateName + "/owners"
)

// NewValidator creates a new Validator that validates the CratesIOAPIToken via
// the Crates.io API endpoint.
//
// It performs a PUT request to the Crates.io API endpoint to add an owner to
// a non-existent crate using the API key in the Authorization header.
// Valid tokens return 404 Not Found, while invalid tokens return 403 Forbidden.
func NewValidator() *simplevalidate.Validator[CratesIOAPItoken] {
	return &simplevalidate.Validator[CratesIOAPItoken]{
		Endpoint:   endpointURL,
		HTTPMethod: http.MethodPut,
		HTTPHeaders: func(key CratesIOAPItoken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + key.Token,
				"Content-Type":  "application/json",
			}
		},
		Body:                 buildRequestBody,
		ValidResponseCodes:   []int{http.StatusNotFound},
		InvalidResponseCodes: []int{http.StatusForbidden},
	}
}

func buildRequestBody(key CratesIOAPItoken) (string, error) {
	payload := map[string][]string{
		"users": {randomUserName},
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}
