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

// Package gitbasicauth contains common logic for Git Basic Auth plugins.
package gitbasicauth

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// URLer is an interface that wraps the URL method.
type URLer interface {
	URL() string
}

// NewValidator creates a new Validator that validates git basic auth credentials using the
// info/refs API
func NewValidator[T URLer](isURLValid func(*url.URL) bool, validCodes, invalidCodes []int) *simplevalidate.Validator[T] {
	return &simplevalidate.Validator[T]{
		EndpointFunc: func(c T) (string, error) {
			u, err := url.Parse(c.URL())
			if err != nil {
				return "", fmt.Errorf("error parsing URL: %w", err)
			}
			// redundant host validation kept intentionally as a security measure in case any regression
			// is introduced in the detector.
			if !isURLValid(u) {
				return "", fmt.Errorf("invalid URL %q", u)
			}

			u = u.JoinPath("info/refs")
			u.RawQuery = "service=git-upload-pack"
			return u.String(), nil
		},
		HTTPMethod:           http.MethodGet,
		ValidResponseCodes:   validCodes,
		InvalidResponseCodes: invalidCodes,
	}
}

// HasValidCredentials returns true if a given url has valid credentials
func HasValidCredentials(u *url.URL) bool {
	if u.User == nil || u.User.Username() == "" {
		return false
	}
	_, hasPassword := u.User.Password()
	return hasPassword
}
