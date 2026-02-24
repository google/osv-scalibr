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

package mongodbatlasaccesstoken

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type cat = MongoDBAtlasAccessToken

const (
	// accessTokenEndpoint is the MongoDB Atlas API v2 clusters endpoint used to
	// validate access tokens.
	accessTokenEndpoint = "https://cloud.mongodb.com/api/atlas/v2/clusters"
)

// NewAccessTokenValidator creates a new MongoDB Atlas Access Token Validator.
// It performs a GET request to the MongoDB Atlas API v2 clusters endpoint
// using the access token in the Authorization header. If the request returns
// HTTP 200, the token is considered valid. If 401 Unauthorized, the token
// is invalid. Other errors return ValidationFailed.
//
// See: https://www.mongodb.com/docs/atlas/reference/api-resources-spec/v2/
func NewAccessTokenValidator() *sv.Validator[cat] {
	return &sv.Validator[cat]{
		Endpoint:   accessTokenEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s cat) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + s.Token,
				"Accept":        "application/vnd.atlas.2025-03-12+json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
