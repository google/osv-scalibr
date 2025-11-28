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

// Package gitbasicauth contains common logic for Git basic auth.
package gitbasicauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/osv-scalibr/veles"
)

// Credentials contains git basic auth credentials.
type Credentials struct {
	Username string
	Password string
}

// Validate validates git credential against the given repoUrl.
func Validate(ctx context.Context, cli *http.Client, repoUrl *url.URL, creds Credentials) (veles.ValidationStatus, error) {
	u := repoUrl.JoinPath("info/refs")
	u.RawQuery = "service=git-upload-pack"

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error building request: %w", err)
	}
	req.SetBasicAuth(creds.Username, creds.Password)

	resp, err := cli.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return veles.ValidationValid, nil
	}

	return veles.ValidationInvalid, nil
}
