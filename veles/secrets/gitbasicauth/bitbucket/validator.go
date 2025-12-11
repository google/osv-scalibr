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

package bitbucket

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth"
)

// NewValidator creates a new Validator that validates Bitbucket credentials
func NewValidator() *simplevalidate.Validator[Credentials] {
	return &simplevalidate.Validator[Credentials]{
		EndpointFunc: func(c Credentials) (string, error) {
			u, err := url.Parse(c.FullURL)
			if err != nil {
				return "", fmt.Errorf("error parsing URL: %w", err)
			}
			// redundant host validation kept intentionally as a security measure in case any regression
			// is introduced in the detector.
			if u.Host != "bitbucket.org" {
				return "", fmt.Errorf("not a valid Bitbucket host %q", u.Host)
			}
			return gitbasicauth.Info(u).String(), nil
		},
		HTTPMethod:           http.MethodGet,
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
