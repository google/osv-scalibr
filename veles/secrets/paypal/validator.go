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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	httpClientTimeout = 10 * time.Second
	// paypalLiveTokenEndpoint is the PayPal OAuth2 token endpoint for Live
	// credentials.
	paypalLiveTokenEndpoint = "https://api-m.paypal.com/v1/oauth2/token"
	// paypalSandboxTokenEndpoint is the PayPal OAuth2 token endpoint for
	// Sandbox credentials.
	paypalSandboxTokenEndpoint = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
)

// Ensure Validator satisfies the Veles Validator interface at compile time.
var _ veles.Validator[Credentials] = &Validator{}

// Validator validates PayPal credentials by attempting the OAuth2
// client_credentials grant against the PayPal token endpoint.
//
// It POSTs to the Live endpoint first and, if the credentials are not valid
// there, retries against the Sandbox endpoint, since a given credential pair
// is scoped to exactly one of the two environments. A 200 response means the
// credentials are valid; a 401 means they are invalid; anything else (5xx,
// network, timeout) is reported as indeterminate (ValidationFailed).
type Validator struct {
	// HTTPC is the HTTP client used for validation requests. Exported to allow
	// injection of test clients.
	HTTPC *http.Client
}

// NewValidator creates a new PayPal credential Validator.
func NewValidator() *Validator {
	return &Validator{
		HTTPC: &http.Client{Timeout: httpClientTimeout},
	}
}

// Validate checks whether the given PayPal Credentials are valid by attempting
// to obtain an OAuth2 access token.
func (v *Validator) Validate(ctx context.Context, c Credentials) (veles.ValidationStatus, error) {
	// Try the Live endpoint first.
	status, err := v.tryEndpoint(ctx, paypalLiveTokenEndpoint, c)
	if err != nil {
		return veles.ValidationFailed, err
	}
	if status == veles.ValidationValid {
		return veles.ValidationValid, nil
	}

	// Not valid on Live: the pair may be scoped to Sandbox.
	return v.tryEndpoint(ctx, paypalSandboxTokenEndpoint, c)
}

func (v *Validator) tryEndpoint(ctx context.Context, endpoint string, c Credentials) (veles.ValidationStatus, error) {
	body := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("building request failed: %w", err)
	}

	// Set Basic Auth header with Client ID and Client Secret.
	authStr := base64.StdEncoding.EncodeToString([]byte(c.ID + ":" + c.Secret))
	req.Header.Set("Authorization", "Basic "+authStr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.HTTPC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("POST failed: %w", err)
	}
	defer resp.Body.Close()
	// Consume the body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
