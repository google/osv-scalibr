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

package azuretoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/jwt"
)

// JWT payload claim keys used to identify Azure tokens.
// Reference: https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#payload-claims
const (
	// payloadIssuerKey represents the 'iss' (issuer) claim.
	payloadIssuerKey = "iss"

	// payloadScopeKey represents the 'scp' (scope) claim.
	payloadScopeKey = "scp"
)

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a Detector that extracts and validates Azure tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return jwt.MaxTokenLength
}

// Detect checks whether a JWT is a valid Azure token.
// It verifies that the token has a valid structure and an accepted Azure issuer
// ('iss').
//
// If the token contains the scope ('scp') claim is then classified as
// access token, otherwise as id token.
//
// References:
//   - https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols
//   - https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
//   - https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens
func (d *detector) Detect(data []byte) (secrets []veles.Secret, positions []int) {
	if len(data) > jwt.MaxTokenLength {
		return nil, nil
	}

	tokens, positions := jwt.ExtractTokens(data)
	for i, t := range tokens {
		payloadClaims := t.Payload()

		// Validate Azure issuer.
		iss, ok := payloadClaims[payloadIssuerKey].(string)
		if !ok || !isValidAzureIssuer(iss) {
			continue
		}

		// Differentiate between access token and id token.
		_, hasScope := payloadClaims[payloadScopeKey]

		if hasScope {
			secrets = append(secrets, AzureAccessToken{Token: t.Raw()})
			positions = append(positions, positions[i])
		} else {
			secrets = append(secrets, AzureIdentityToken{Token: t.Raw()})
			positions = append(positions, positions[i])
		}
	}

	return secrets, positions
}

// According to the Azure documentation, access/id tokens can be issued by:
//   - https://login.microsoftonline.com/{tenant-id}/v2.0
//   - https://sts.windows.net/{tenant-id}/
//
// Both forms include a tenant ID as a 36-character GUID
var (
	reLoginMicrosoft = regexp.MustCompile(`^https://login\.microsoftonline\.com/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/v2\.0$`)
	reStsWindows     = regexp.MustCompile(`^https://sts\.windows\.net/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/?$`)
)

// isValidAzureIssuer reports whether the given issuer ('iss') URL matches
// one of the valid Azure issuer formats.
func isValidAzureIssuer(iss string) bool {
	return reLoginMicrosoft.MatchString(iss) || reStsWindows.MatchString(iss)
}
