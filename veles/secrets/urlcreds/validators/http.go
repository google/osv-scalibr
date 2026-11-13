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
	"time"

	"github.com/doyensec/safeurl"
	"github.com/google/osv-scalibr/veles"
	"github.com/icholy/digest"
)

// HTTPValidator validates a URL using Basic or Digest authentication.
type HTTPValidator struct{ Client *http.Client }

var publicTransport = newPublicTransport()

// NewHTTPClient returns an HTTP client using the same protected transport as the
// FTP/SFTP dialer. Every connection, including redirects, is checked by safeurl.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: publicTransport,
		Timeout:   10 * time.Second,
	}
}

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
		if err := setDigestAuth(req, u.User, authHeader); err != nil {
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

func newPublicTransport() *http.Transport {
	// Credential URLs may use nonstandard ports. Restrict destinations rather
	// than ports, preserving validation of public services on arbitrary ports.
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	config := safeurl.GetConfigBuilder().
		SetAllowedPorts(ports...).
		EnableIPv6(true).
		Build()
	// safeurl constructs an *http.Transport with a protected DialContext. No
	// proxy is configured: it could resolve the destination outside this policy.
	// Authentication is supplied through headers, never URL userinfo.
	return safeurl.Client(config).Client.Transport.(*http.Transport)
}

func setDigestAuth(req *http.Request, userInfo *url.Userinfo, authHeader string) error {
	challenge, err := digest.ParseChallenge(authHeader)
	if err != nil {
		return fmt.Errorf("error pasing the server challenge: %w", err)
	}
	pass, _ := userInfo.Password()
	cred, _ := digest.Digest(challenge, digest.Options{
		Username: userInfo.Username(),
		Password: pass,
		Method:   req.Method,
		URI:      req.URL.RequestURI(),
		GetBody:  req.GetBody,
		Count:    1,
	})
	req.Header.Set("Authorization", cred.String())
	return nil
}
