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

package mongodbatlasapikey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/veles"
)

const (
	// atlasEndpoint is the MongoDB Atlas Admin API v2 endpoint used for validation.
	atlasEndpoint = "https://cloud.mongodb.com/api/atlas/v2"
)

// Validator validates MongoDB Atlas API keys via the Atlas Admin API
// using HTTP Digest Authentication.
type Validator struct {
	// Endpoint overrides the default Atlas API endpoint (for testing).
	Endpoint string
	// HTTPC is the HTTP client to use. Uses http.DefaultClient if nil.
	HTTPC *http.Client
}

// NewValidator creates a new Validator for MongoDB Atlas API keys.
func NewValidator() *Validator {
	return &Validator{}
}

// Validate validates a MongoDB Atlas API key pair by performing HTTP Digest
// Authentication against the Atlas Admin API v2.
//
// A GET request is sent to the API root endpoint. If the server responds with
// HTTP 200, the key is valid. If 401 after digest auth, the key is invalid.
// Digest auth is handled by the shared HTTPAuthentication client from
// clients/datasource, which implements RFC 2617.
func (v *Validator) Validate(ctx context.Context, secret APIKey) (veles.ValidationStatus, error) {
	if secret.PublicKey == "" || secret.PrivateKey == "" {
		return veles.ValidationInvalid, nil
	}

	client := v.HTTPC
	if client == nil {
		client = http.DefaultClient
	}

	endpoint := v.Endpoint
	if endpoint == "" {
		endpoint = atlasEndpoint
	}

	auth := &datasource.HTTPAuthentication{
		SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthDigest},
		Username:         secret.PublicKey,
		Password:         secret.PrivateKey,
	}

	resp, err := auth.Get(ctx, client, endpoint)
	if err != nil {
		if ctx.Err() != nil {
			return veles.ValidationFailed, ctx.Err()
		}
		return veles.ValidationFailed, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusForbidden:
		// 403 means the key is valid but lacks permissions for this endpoint.
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}
