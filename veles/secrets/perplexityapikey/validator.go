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

package perplexityapikey

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type pak = PerplexityAPIKey

// NewValidator creates a new Perplexity API key Validator with the given Options.
// It performs a GET request to the Perplexity chat completions endpoint
// using the API key in the Authorization header. If the request returns
// HTTP 200, the key is considered valid. If 401 Unauthorized, the key
// is invalid. Other errors return ValidationFailed.
func NewValidator(opts ...sv.Option[pak]) *sv.Validator[pak] {
	return sv.New(append([]sv.Option[pak]{
		sv.WithEndpoint[pak]("https://api.perplexity.ai/async/chat/completions"),
		sv.WithHTTPMethod[pak](http.MethodGet),
		sv.WithHTTPHeaders(func(s pak) map[string]string {
			return map[string]string{"Authorization": "Bearer " + s.Key}
		}),
		sv.WithValidResponseCodes[pak]([]int{http.StatusOK}),
		sv.WithInvalidResponseCodes[pak]([]int{http.StatusUnauthorized}),
	}, opts...)...)
}
