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

package validators

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/urlcreds/validators/httpauth"
)

// HTTPValidator validates a URL using Basic or Digest authentication.
type HTTPValidator struct{ Client *http.Client }

// Validate implements the standard challenge-response mechanism.
// It sends an unauthenticated probe first, then attempts authentication
// based on the server's response.
func (h *HTTPValidator) Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error) {
	// Strip user info to force a 401 challenge.
	probeURL := *u
	probeURL.User = nil

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error doing the first request: %w", err)
	}
	resp.Body.Close()

	// A 401 status is expected to proceed with validation.
	if resp.StatusCode != http.StatusUnauthorized {
		return veles.ValidationFailed, fmt.Errorf("unexpected status during probe: %s", resp.Status)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	// Add probe response cookies
	// This was needed when testing against flask_httpauth.HTTPDigestAuth.
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}

	// Check the WWW-Authenticate header.
	authHeader := resp.Header.Get("WWW-Authenticate")
	switch {
	case strings.HasPrefix(authHeader, "Digest "):
		if err := httpauth.SetDigestAuth(req, u.User, authHeader); err != nil {
			return veles.ValidationFailed, fmt.Errorf("error adding Digest header: %w", err)
		}
	default:
		// Use Basic Auth as default
		password, _ := u.User.Password()
		req.SetBasicAuth(u.User.Username(), password)
	}

	resp, err = h.Client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error doing the authenticated request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
