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

package sap

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewSAPSuccessFactorsAccessTokenValidator creates a new SAP Success Factors Access Token Validator.
//
// It performs a GET request to the SAP Success Factors OAuth2 token validation endpoint.
// If the request returns HTTP 200, the credentials are valid.
// If 401 Unauthorized, they are invalid.
// Reference:
// https://help.sap.com/docs/successfactors-platform/sap-successfactors-api-reference-guide-odata-v4/viewing-validity-of-access-token
// https://help.sap.com/docs/successfactors-platform/sap-successfactors-api-reference-guide-odata-v4/list-of-sap-successfactors-api-servers#endpoint-url-patterns
func NewSAPSuccessFactorsAccessTokenValidator() *sv.Validator[SuccessFactorsAccessToken] {
	return &sv.Validator[SuccessFactorsAccessToken]{
		Endpoints:  []string{"https://api10.successfactors.com/oauth/validate", "https://api10preview.sapsf.com/oauth/validate", "https://api012.successfactors.eu/oauth/validate", "https://api12preview.sapsf.eu/oauth/validate", "https://api15.sapsf.cn/oauth/validate", "https://api15preview.sapsf.cn/oauth/validate", "https://api17preview.sapsf.com/oauth/validate", "https://api17.sapsf.com/oauth/validate", "https://api19preview.sapsf.com/oauth/validate", "https://api19preview.sapsf.com/oauth/validate", "https://api2.successfactors.eu/oauth/validate", "https://api.successfactors.eu/oauth/validate", "https://apisalesdemo2.successfactors.eu/oauth/validate", "https://api2preview.sapsf.eu/oauth/validate", "https://api22preview.sapsf.com/oauth/validate", "https://api22.sapsf.com/oauth/validate", "https://api23preview.sapsf.com/oauth/validate", "https://api23.sapsf.com/oauth/validate", "https://api4.successfactors.com/oauth/validate", "https://api4preview.sapsf.com/oauth/validate", "https://api68sales.successfactors.com/oauth/validate", "https://api40sales.sapsf.com/oauth/validate", "https://api41preview.sapsf.com/oauth/validate", "https://api41.sapsf.com/oauth/validate", "https://api44preview.sapsf.com/oauth/validate", "https://api44.sapsf.com/oauth/validate", "https://api47preview.sapsf.com/oauth/validate", "https://api47.sapsf.com/oauth/validate", "https://api50preview.sapsf.com/oauth/validate", "https://api50.sapsf.com/oauth/validate", "https://api55preview.sapsf.eu/oauth/validate", "https://api55.sapsf.eu/oauth/validate", "https://api74preview.sapsf.euoauth/validate", "https://api74.sapsf.euoauth/validate", "https://api8.successfactors.com/oauth/validate", "https://apisalesdemo8.successfactors.com/oauth/validate", "https://api8preview.sapsf.com/oauth/validate", "https://api-in10.hr.cloud.sap/oauth/validate", "https://api-in10-preview.hr.cloud.sap/oauth/validate", "https://api-sa20.hr.cloud.sap/oauth/validate", "https://api-sa20-preview.hr.cloud.sap/oauth/validate"},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(creds SuccessFactorsAccessToken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + creds.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusInternalServerError},
	}
}
