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

package hashicorpvault

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Vault token.
const maxTokenLength = 200

// maxUUIDLength is the maximum size of a UUID (AppRole credential).
const maxUUIDLength = 36

// vaultTokenRe is a regular expression that matches HashiCorp Vault tokens.
// Vault tokens start with "hvs." or "hvp." followed by base64-like characters.
var vaultTokenRe = regexp.MustCompile(`hv[sp]\.[A-Za-z0-9_-]{20,}`)

// appRoleCredentialRe is a regular expression that matches UUID v4 format used for AppRole credentials.
// UUIDs have the format: 8-4-4-4-12 hexadecimal digits separated by hyphens.
var appRoleCredentialRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// NewTokenDetector returns a new simpletoken.Detector that matches HashiCorp Vault tokens.
func NewTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     vaultTokenRe,
		FromMatch: func(b []byte) veles.Secret {
			return Token{Token: string(b)}
		},
	}
}

// NewAppRoleDetector returns a new simpletoken.Detector that matches UUID-formatted AppRole credentials.
// Note: This detector identifies potential AppRole credentials, but cannot distinguish between
// role-id and secret-id without additional context. Both are returned as AppRoleCredentials
// with the UUID in the RoleID field for simplicity.
func NewAppRoleDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxUUIDLength,
		Re:     appRoleCredentialRe,
		FromMatch: func(b []byte) veles.Secret {
			uuid := string(b)
			// Since we can't distinguish role-id from secret-id in isolation,
			// we store the UUID as a potential credential
			return AppRoleCredentials{RoleID: uuid, SecretID: ""}
		},
	}
}
