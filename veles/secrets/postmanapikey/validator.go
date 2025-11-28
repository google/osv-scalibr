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

package postmanapikey

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// API endpoint that returns authenticated user info when the API key is valid.
	// We call /me with X-Api-Key header.
	apiEndpoint = "https://api.getpostman.com/me"
	// A dummy collection ID used to produce predictable authentication vs
	// authorization responses when validating collection access tokens.
	//
	// Postman's collection endpoint requires both authentication and
	// authorization. Using a collection ID we don't own
	// ("aaaaaaaa-aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa") means that a valid
	// collection access token will authenticate successfully but will
	// typically receive a 403 Forbidden because the token is not authorized
	// for that collection. An invalid token will produce a 401 Authentication
	// error. This predictable difference lets us distinguish a valid token
	// (authenticated but not authorized) from an invalid one.
	dummyCollectionID  = "aaaaaaaa-aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa"
	collectionEndpoint = "https://api.postman.com/collections/" + dummyCollectionID
	validationTimeout  = 10 * time.Second
	// Exact values observed for a valid-but-not-authorized response.
	forbiddenErrorName = "forbiddenError"
)

// NewAPIValidator creates a new Validator that validates Postman API keys
// (PMAK-...) using /me endpoint.
// It calls GET /me with header "X-Api-Key: <key>".
// - 200 OK  -> authenticated and valid.
// - 401     -> invalid API key (authentication failure).
// - other   -> validation failed (unexpected response).
func NewAPIValidator() *simplevalidate.Validator[PostmanAPIKey] {
	return &simplevalidate.Validator[PostmanAPIKey]{
		Endpoint:   apiEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k PostmanAPIKey) map[string]string {
			return map[string]string{"X-Api-Key": k.Key}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}

// collectionErrorResponse models Postman's collection endpoint error JSON.
type collectionErrorResponse struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}

func statusFromCollectionResponseBody(body io.Reader, _ PostmanCollectionToken, _ *http.Request) (veles.ValidationStatus, error) {
	var resp collectionErrorResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		// Decoding failed -> ambiguous response, treat as failed to validate.
		return veles.ValidationFailed, fmt.Errorf("unable to parse response: %w", err)
	}
	if resp.Error.Name == forbiddenErrorName {
		// Exact match -> authenticated but not authorized for dummy
		// collection, therefore token is valid.
		return veles.ValidationValid, nil
	}
	// 403 with different payload -> treat as invalid (conservative).
	return veles.ValidationInvalid, nil
}

// NewCollectionValidator creates a new Validator that validates Postman
// collection access tokens (PMAT-...).
// It calls GET {collectionEndpoint}?access_key=<token> using a dummy
// collection ID. The dummy collection ID is used to create a predictable
// authorization failure for valid tokens (403 Forbidden) while invalid
// tokens produce 401 Authentication errors.
//
// Interpretation of statuses:
//   - 200 OK  -> token is valid and authorized for the collection (rare here).
//   - 403     -> authenticated but not authorized for this collection -> valid
//     *only if* StatusFromResponseBody returns ValidationValid based on
//     Postman's JSON response for that situation:
//     {"error":{"name":"forbiddenError","message":"You are not authorized to perform this action."}}
//   - 401     -> invalid token (authentication failure).
//   - other   -> validation failed.
func NewCollectionValidator() *simplevalidate.Validator[PostmanCollectionToken] {
	return &simplevalidate.Validator[PostmanCollectionToken]{
		EndpointFunc: func(k PostmanCollectionToken) (string, error) {
			return collectionEndpoint + "?access_key=" + k.Key, nil
		},
		HTTPMethod:             http.MethodGet,
		ValidResponseCodes:     []int{http.StatusOK},
		InvalidResponseCodes:   []int{http.StatusUnauthorized},
		StatusFromResponseBody: statusFromCollectionResponseBody,
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
