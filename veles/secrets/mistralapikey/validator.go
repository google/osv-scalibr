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

package mistralapikey

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// mistralModelsEndpoint is the API endpoint to list Mistral models.
	mistralModelsEndpoint = "https://api.mistral.ai/v1/models"
)

// NewValidator creates a new Validator that validates the MistralAPIKey via
// the Mistral API.
//
// It performs a GET request to the models endpoint.
// - 200 OK: Valid Secret.
// - 401 Unauthorized: Invalid Secret.
func NewValidator() *sv.Validator[MistralAPIKey] {
	return &sv.Validator[MistralAPIKey]{
		Endpoint:   mistralModelsEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s MistralAPIKey) map[string]string {
			return map[string]string{"Authorization": "Bearer " + s.Key}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
