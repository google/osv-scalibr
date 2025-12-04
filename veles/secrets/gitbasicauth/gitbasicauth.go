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

// Package gitbasicauth contains common logic for Git Basic Auth plugins.
package gitbasicauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Info performs the info/refs request for Git upload-pack service.
// It returns the HTTP status code and an optional error.
func Info(ctx context.Context, cli *http.Client, repoURL *url.URL) (int, error) {
	u := repoURL.JoinPath("info/refs")
	u.RawQuery = "service=git-upload-pack"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("error building request: %w", err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}
