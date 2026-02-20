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

package ibmclouduserkey

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type pak = IBMCloudUserSecret

// NewValidator checks whether the given IBMCloudUserSecret is valid.
//
// It calls POST https://iam.cloud.ibm.com/identity/token with Bearer token.
// - 200 OK -> authenticated and valid.
// - 400 Bad Request -> invalid.
func NewValidator() *sv.Validator[pak] {
	return &sv.Validator[pak]{
		Endpoint:   "https://iam.cloud.ibm.com/identity/token",
		HTTPMethod: http.MethodPost,
		Body: func(s pak) (string, error) {
			// IBM Cloud requires apikey parameter in body for API key validation
			return "grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=" + s.Key, nil
		},
		HTTPHeaders: func(_ pak) map[string]string {
			return map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusBadRequest},
	}
}
