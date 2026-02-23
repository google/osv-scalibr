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

package paypal

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	httpClientTimeout = 10 * time.Second
	// PayPal OAuth2 token endpoint for live credentials.
	paypalLiveTokenEndpoint = "https://api-m.paypal.com/v1/oauth2/token"
	// PayPal OAuth2 token endpoint for sandbox credentials.
	paypalSandboxTokenEndpoint = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
)

// ClientIDSecretPair holds a PayPal Client ID and Client Secret pair for
// validation. Since PayPal requires both the Client ID and Client Secret
// to authenticate, the validator needs both values.
type ClientIDSecretPair struct {
	ClientID     string
	ClientSecret string
}

// Validator validates PayPal credentials by attempting to obtain an OAuth2
// access token using the Client ID and Client Secret pair.
//
// It calls POST https://api-m.paypal.com/v1/oauth2/token with Basic Auth
// (client_id:client_secret) and grant_type=client_credentials.
//
// If the response is 200 OK, the credentials are considered valid.
// If the response is 401 Unauthorized, the credentials are invalid.
// Other status codes result in a failed validation (indeterminate).
type Validator struct {
	// HTTPC is the HTTP client used for validation requests.
	// Exported to allow injection of test clients.
	HTTPC *http.Client
}

// NewValidator creates a new PayPal credential validator.
func NewValidator() *Validator {
	return &Validator{
		HTTPC: &http.Client{Timeout: httpClientTimeout},
	}
}

// Validate checks if the given PayPal credential pair is valid by attempting
// to obtain an OAuth2 access token.
func (v *Validator) Validate(ctx context.Context, pair ClientIDSecretPair) (veles.ValidationStatus, error) {
	// Try the live endpoint first.
	status, err := v.tryEndpoint(ctx, paypalLiveTokenEndpoint, pair)
	if err != nil {
		return veles.ValidationFailed, err
	}
	if status == veles.ValidationValid {
		return veles.ValidationValid, nil
	}

	// If the live endpoint returns invalid, also try sandbox.
	status, err = v.tryEndpoint(ctx, paypalSandboxTokenEndpoint, pair)
	if err != nil {
		return veles.ValidationFailed, err
	}
	return status, nil
}

func (v *Validator) tryEndpoint(ctx context.Context, endpoint string, pair ClientIDSecretPair) (veles.ValidationStatus, error) {
	body := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return veles.ValidationFailed, err
	}

	// Set Basic Auth header with Client ID and Client Secret.
	authStr := base64.StdEncoding.EncodeToString(
		[]byte(pair.ClientID + ":" + pair.ClientSecret),
	)
	req.Header.Set("Authorization", "Basic "+authStr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.HTTPC.Do(req)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer resp.Body.Close()
	// Consume the body to allow connection reuse.
	io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationInvalid, nil
	}
}
