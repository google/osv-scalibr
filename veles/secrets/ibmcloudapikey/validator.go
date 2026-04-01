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

package ibmcloudapikey

import (
	"net/http"
	"net/url"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewValidator creates a Validator for IBM Cloud API keys.
// It validates by exchanging the API key for an IAM access token.
// A successful exchange (200) means the key is valid.
// An error response (400, 401) means the key is invalid.
func NewValidator() *simplevalidate.Validator[Secret] {
	return &simplevalidate.Validator[Secret]{
		Endpoint:   "https://iam.cloud.ibm.com/identity/token",
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(_ Secret) map[string]string {
			return map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Accept":       "application/json",
			}
		},
		Body: func(s Secret) (string, error) {
			return url.Values{
				"grant_type": {"urn:ibm:params:oauth:grant-type:apikey"},
				"apikey":     {s.Key},
			}.Encode(), nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusBadRequest, http.StatusUnauthorized},
	}
}
