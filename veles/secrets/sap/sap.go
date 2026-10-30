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

// Package sap contains Veles Secret types and Detectors for SAP Client Credentials and Access tokens.
package sap

// AccessToken is SAP BTP Access Token
type AccessToken struct {
	// Token is the SAP Access Token
	Token string
	// URL is the SAP URL
	URL string
}

// SuccessFactorsAccessToken is SAP Success Factors Access Token
type SuccessFactorsAccessToken struct {
	// Token is the Access Token
	Token string
}

// ConcurAccessToken is SAP Concur Access Token
type ConcurAccessToken struct {
	// Token is the Access Token
	Token string
}

// ConcurRefreshToken represents SAP Concur Refresh Token Credentials
type ConcurRefreshToken struct {
	// ID is OAuth2 Client ID
	ID string
	// Secret is OAuth2 Client Secret
	Secret string
	// Token is the Refresh Token
	Token string
}

// AribaOAuth2ClientCredentials represents SAP Ariba OAuth2 Client Credentials.
type AribaOAuth2ClientCredentials struct {
	// ID is OAuth2 Client ID
	ID string
	// Secret is OAuth2 Client Secret
	Secret string
}

// BTPOAuth2ClientCredentials represents SAP BTP OAuth2 Client Credentials.
// SAP HANA uses BTP for Authentication
type BTPOAuth2ClientCredentials struct {
	// ID is the SAP OAuth2 Client ID
	ID string
	// Secret is the SAP OAuth2 Client Secret
	Secret string
	// TokenURL is the SAP Token URL
	TokenURL string
}
