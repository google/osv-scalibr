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

// Package databricks contains Veles Secret types and Detectors for Databricks Client Credentials and PATs.
package databricks

import (
	"regexp"
)

const (
	// maxTokenLength is the maximum length of a valid Databricks User Account Personal Access Token.
	// There is no documented length.
	// An official example suggests it's 36 characters in length:
	// Reference: https://docs.databricks.com/api/gcp/workspace/tokenmanagement/createobotoken
	// However, real word demonstrations from youtube suggest that it's somewhere between 36 to 40:
	// Length 36: https://youtu.be/yyy7LA4H4co?t=682&si=lS0VuWNJ8ciPh9OC
	// Length 38: https://youtube.com/shorts/nM-2L-taB1M?si=CTwdfH17xm-ySsG_
	// Length 38: https://youtu.be/4wFygEnkUZw?t=186&si=aMrAjSBN4-xGBjJO
	// Therefore, 38 is a good upper bound.
	maxTokenLength = 38

	// maxIDLength is the maximum length of a valid client ID.
	// There is not documented length.
	// A real demonstration from youtube suggests that it's 36.
	// For reference:
	// https://youtu.be/4wFygEnkUZw?t=271&si=HOwcCVSWh2PxtPjg
	maxIDLength = 36

	// maxSecretLength is the maximum length of a valid client secret.
	// There is not documented length.
	// A real demonstration from youtube suggests that it's 36.
	// For reference:
	// https://youtu.be/4wFygEnkUZw?t=271&si=HOwcCVSWh2PxtPjg
	maxSecretLength = 36

	// maxAccountIDLength is the maximum length of a valid Databricks User Account ID.
	// There is not documented length but we can guess it from the following official demonstration:
	// https://docs.databricks.com/aws/en/admin/account-settings#account-id
	// We can also signup for a free trial and can verify
	// It's exactly 36 in length but if hypens are not include, it'd be 32.
	// We're selecting 50 as the upperbound for contextual matches
	maxAccountIDLength = 50

	// maxURLLength is the maximum length of a valid Databricks Workspace URL.
	// There is not documented length but 100 is a good upper bound.
	maxURLLength = 100

	// maxDistance is the maximum distance between User Account PATs and IDS to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	// tokenRe is a regular expression that matches Databricks Service Principal Personal Access Token.
	// Reference: https://docs.databricks.com/api/gcp/workspace/tokenmanagement/createobotoken
	// Moreover, here are few real word demonstrations on youtube:
	// https://youtu.be/yyy7LA4H4co?t=682&si=lS0VuWNJ8ciPh9OC
	// https://youtube.com/shorts/nM-2L-taB1M?si=CTwdfH17xm-ySsG_
	// https://youtu.be/4wFygEnkUZw?t=186&si=aMrAjSBN4-xGBjJO
	tokenRe = regexp.MustCompile(`\bdapi[A-Za-z0-9._\-]{32,34}\b`)

	// clientIDRe is a regular expression that matches Databricks OAuth2 Client IDs.
	// A real word demonstration on youtube suggests its an UUID-like string:
	// https://youtu.be/4wFygEnkUZw?t=271&si=HOwcCVSWh2PxtPjg
	// Since it's an UUID-like string, it is possible that hypens are not present in the string (edge case).
	// Therefore, I have chosen 32 as the minimum length.
	clientIDRe = regexp.MustCompile(`(?i)\bclient[_-]?id\b\s*[:=]?\s*([A-Za-z0-9\-]{32,36})\b`)

	// clientSecretRe is a regular expression that matches Databricks OAuth2 Client Secrets.
	// A real word demonstration on youtube suggests it starts with "dose" prefix followed by an alphanumeric string:
	// https://youtu.be/4wFygEnkUZw?t=271&si=HOwcCVSWh2PxtPjg
	clientSecretRe = regexp.MustCompile(`\bdose[A-Za-z0-9._\-]{32}\b`)

	// accountIDRe is a regular expression that matches Databricks User Account ID.
	// Reference: https://docs.databricks.com/aws/en/admin/account-settings#account-id
	accountIDRe = regexp.MustCompile(`(?i)\baccount[_-]?id\b\s*[:=]?\s*([A-Za-z0-9\-]{32,36})\b`)
)

// SPOAuth2ClientCredentials represents a Databricks Service Principal OAuth2 Client Credentials.
type SPOAuth2ClientCredentials struct {
	// URL is the Databricks Service Principal Workspace URL
	URL string
	// Secret is the Databricks Service Principal OAuth2 Client Secret
	Secret string
	// ID is the Databricks Service Principal OAuth2 Client ID
	ID string
}

// UAOAuth2ClientCredentials represents a Databricks User Account OAuth2 Client Credentials.
type UAOAuth2ClientCredentials struct {
	// ID is the Databricks User Account OAuth2 Client ID
	ID string
	// Secret is the Databricks User Account OAuth2 Client Secret
	Secret string
	// AccountID is the Databricks User Account ID
	AccountID string
}

// SPPATCredentials represents a Databricks Service Principal Personal Access Token Credentials.
type SPPATCredentials struct {
	// Token is the Databricks Service Principal Personal Access Token
	Token string
	// URL is the Databricks Service Principal Workspace URL
	URL string
}

// UAPATCredentials represents a Databricks User Account Personal Access Token Credentials.
type UAPATCredentials struct {
	// Token is the Databricks User Account Personal Access Token
	Token string
	// AccountID is the Databricks User Account ID
	AccountID string
}
