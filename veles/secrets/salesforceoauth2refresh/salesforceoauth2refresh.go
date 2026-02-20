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

// Package salesforceoauth2refresh contains Veles Secret types and Detectors for Salesforce OAuth2 client credentials.
package salesforceoauth2refresh

// Credentials represents a Salesforce OAuth2 client credential.
//
// See:
// - https://help.salesforce.com/s/articleView?language=en_US&id=sf.remoteaccess_oauth_client_credentials_flow.htm&type=5
// - https://help.salesforce.com/s/articleView?language=en_US&id=xcloud.remoteaccess_oauth_refresh_token_flow.htm&type=5
type Credentials struct {
	// ID is the client ID
	ID string
	// Secret is the client secret
	Secret string
	// Refresh is the refresh token
	Refresh string
}
