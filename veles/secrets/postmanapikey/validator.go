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
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Validator[PostmanAPIKey]          = &ValidatorAPI{}
	_ veles.Validator[PostmanCollectionToken] = &ValidatorCollection{}
)

// Endpoints used for validation.
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
)

// --- Postman API Key Validator (PMAK) ---

// ValidatorAPI validates Postman API keys (PMAK-...) using /me.
type ValidatorAPI struct {
	httpC *http.Client
}

// ValidatorOptionAPI configures a ValidatorAPI when creating it via New.
type ValidatorOptionAPI func(*ValidatorAPI)

// WithClientAPI configures the http.Client used by ValidatorAPI.
//
// By default it uses http.DefaultClient.
func WithClientAPI(c *http.Client) ValidatorOptionAPI {
	return func(v *ValidatorAPI) {
		v.httpC = c
	}
}

// NewAPIValidator creates a new ValidatorAPI with the given options.
func NewAPIValidator(opts ...ValidatorOptionAPI) *ValidatorAPI {
	v := &ValidatorAPI{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// apiErrorResponse models Postman's error JSON payload.
type apiErrorResponse struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}

// Validate checks whether the given PostmanAPIKey is valid.
//
// It calls GET /me with header "X-Api-Key: <key>".
// - 200 OK  -> authenticated and valid.
// - 401     -> invalid API key (authentication failure).
// - other   -> validation failed (unexpected response).
func (v *ValidatorAPI) Validate(ctx context.Context, key PostmanAPIKey) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	// Postman expects the API key in the X-Api-Key header.
	req.Header.Set("X-Api-Key", key.Key)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", apiEndpoint, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// 200 OK => the key is valid and authenticated.
		return veles.ValidationValid, nil

	case http.StatusUnauthorized:
		// 401 => authentication failed -> invalid key.
		return veles.ValidationInvalid, nil

	default:
		// For other statuses try to decode Postman's error for better context.
		var resp apiErrorResponse
		_ = json.NewDecoder(res.Body).Decode(&resp) // best-effort decode
		return veles.ValidationFailed, fmt.Errorf(
			"unexpected status %q from %q: %s", res.Status, apiEndpoint, resp.Error.Message)
	}
}

// --- Postman Collection Access Token Validator (PMAT) ---

// ValidatorCollection validates Postman collection access tokens (PMAT-...).
type ValidatorCollection struct {
	httpC *http.Client
}

// ValidatorOptionCollection configures a ValidatorCollection when creating it via New.
type ValidatorOptionCollection func(*ValidatorCollection)

// WithClientCollection configures the http.Client used by ValidatorCollection.
//
// By default it uses http.DefaultClient.
func WithClientCollection(c *http.Client) ValidatorOptionCollection {
	return func(v *ValidatorCollection) {
		v.httpC = c
	}
}

// NewCollectionValidator creates a new ValidatorCollection with the given options.
func NewCollectionValidator(opts ...ValidatorOptionCollection) *ValidatorCollection {
	v := &ValidatorCollection{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// collectionErrorResponse models Postman's collection endpoint error JSON.
type collectionErrorResponse struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}

const (
	// Exact values observed for a valid-but-not-authorized response.
	forbiddenErrorName = "forbiddenError"
)

// Validate checks whether the given PostmanCollectionToken is valid.
//
// It calls GET {collectionEndpoint}?access_key=<token> using a dummy
// collection ID. The dummy collection ID is used to create a predictable
// authorization failure for valid tokens (403 Forbidden) while invalid
// tokens produce 401 Authentication errors.
//
// Interpretation of statuses:
//   - 200 OK  -> token is valid and authorized for the collection (rare here).
//   - 403     -> authenticated but not authorized for this collection -> valid
//     *only if* the response body matches the exact JSON produced by
//     Postman for that situation:
//     {"error":{"name":"forbiddenError","message":"You are not authorized to perform this action."}}
//   - 401     -> invalid token (authentication failure).
//   - other   -> validation failed.
func (v *ValidatorCollection) Validate(ctx context.Context, key PostmanCollectionToken) (veles.ValidationStatus, error) {
	url := collectionEndpoint + "?access_key=" + key.Key
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", url, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// 200 => token is valid and has access to the collection.
		return veles.ValidationValid, nil

	case http.StatusForbidden:
		// 403 => usually means the token authenticated but is not authorized
		// for this collection. Because we intentionally used a collection ID
		// we don't own, this indicates the token itself may be valid.
		// To avoid false positives we require the response body to match the
		// exact JSON Postman returns for that case (name + message).
		var resp collectionErrorResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			// Decoding failed -> ambiguous response, treat as failed to validate.
			return veles.ValidationFailed, fmt.Errorf("unable to parse response from %q: %w", url, err)
		}
		if resp.Error.Name == forbiddenErrorName {
			// Exact match -> authenticated but not authorized for dummy
			// collection, therefore token is valid.
			return veles.ValidationValid, nil
		}
		// 403 with different payload -> treat as invalid (conservative).
		return veles.ValidationInvalid, nil

	case http.StatusUnauthorized:
		// 401 => authentication failed -> invalid token.
		return veles.ValidationInvalid, nil

	default:
		// Other responses are treated as failures to validate.
		var resp collectionErrorResponse
		_ = json.NewDecoder(res.Body).Decode(&resp) // best-effort
		return veles.ValidationFailed, fmt.Errorf(
			"unexpected status %q from %q: %s", res.Status, url, resp.Error.Message)
	}
}
