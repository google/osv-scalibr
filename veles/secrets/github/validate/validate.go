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

// Package validate contains common logic to validate github tokens
package validate

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

// Validate validates a Github token given a client and a path
func Validate(ctx context.Context, client *http.Client, path string, token string) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	//nolint:canonicalheader // This header is set as "X-GitHub-Api-Version" exactly as documented by GitHub.
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer res.Body.Close()
	_, err = io.ReadAll(res.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}

	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, nil
	}
}
