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

package mongodbatlasrefreshtoken

import (
	"net/http"
	"net/url"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type cat = MongoDBAtlasRefreshToken

const (
	// refreshTokenEndpoint is the MongoDB Atlas device token endpoint used to
	// validate refresh tokens by attempting a token refresh.
	refreshTokenEndpoint = "https://cloud.mongodb.com/api/private/unauth/account/device/token"
	// refreshTokenClientID is the Okta client ID used in the refresh token request.
	refreshTokenClientID = "0oabtxactgS3gHIR0297"
)

// NewRefreshTokenValidator creates a new MongoDB Atlas Refresh Token Validator.
// It performs a POST request to the MongoDB Atlas device token endpoint with
// the refresh token in a form-encoded body. If the request returns HTTP 200,
// the refresh token is considered valid. If 401 Unauthorized, the token is
// invalid. Other errors return ValidationFailed.
func NewRefreshTokenValidator() *sv.Validator[cat] {
	return &sv.Validator[cat]{
		Endpoint:   refreshTokenEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(s cat) map[string]string {
			return map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Accept":       "application/json",
			}
		},
		Body: func(s cat) (string, error) {
			params := url.Values{}
			params.Set("client_id", refreshTokenClientID)
			params.Set("refresh_token", s.Token)
			params.Set("scope", "openid profile offline_access")
			params.Set("grant_type", "refresh_token")
			return params.Encode(), nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusBadRequest},
	}
}
