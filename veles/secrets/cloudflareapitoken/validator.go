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

package cloudflareapitoken

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type cat = CloudflareAPIToken

// NewValidator creates a new Cloudflare API Token Validator.
// It performs a GET request to the Cloudflare API zones endpoint
// using the API token in the Authorization header. If the request returns
// HTTP 200, the token is considered valid. If 403 Forbidden, the token
// is invalid. Other errors return ValidationFailed.
//
// See: https://developers.cloudflare.com/api/resources/zones/methods/list/
func NewValidator() *sv.Validator[cat] {
	return &sv.Validator[cat]{
		Endpoint:   "https://api.cloudflare.com/client/v4/zones",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s cat) map[string]string {
			return map[string]string{"Authorization": "Bearer " + s.Token}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusForbidden},
	}
}
