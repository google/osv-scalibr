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

	"github.com/google/osv-scalibr/veles"
)

// HTTPValidator validates a Basic Auth URL with http/https schema.
type HTTPValidator struct{ Client *http.Client }

// Validate validates a Basic Auth URL with http/https schema.
func (h *HTTPValidator) Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := h.Client.Do(req)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return veles.ValidationInvalid, nil
	}

	unauth := *u
	unauth.User = nil

	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, unauth.String(), nil)
	respUnauth, err := h.Client.Do(req)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer respUnauth.Body.Close()

	if respUnauth.StatusCode != http.StatusOK && resp.StatusCode == http.StatusOK {
		return veles.ValidationValid, nil
	}

	return veles.ValidationFailed, fmt.Errorf("unable to validate %q", u.String())
}
