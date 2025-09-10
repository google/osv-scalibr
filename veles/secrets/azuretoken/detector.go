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

// maxTokenLength defines the maximum allowed size of a JWT token.
//
// The JWT specification (RFC 7519) does not define an upper bound for token
// length. However, in practice JWTs are typically transmitted in HTTP headers,
// where very large values can cause interoperability issues. Exceeding 8 KB is
// generally discouraged, as many servers, proxies, and libraries impose limits
// around this size.
const maxTokenLength = 8192

// jwtRe is a regular expression that matches the basic JWT structure (base64.base64.base64)
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a Detector that extracts and validates Azure tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxTokenLength
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
	if len(data) > maxTokenLength {
		return nil, nil
	}

	jwtMatches := jwtRe.FindAllIndex(data, -1)
	for _, m := range jwtMatches {
		token := string(data[m[0]:m[1]])
		claims := jwt.ExtractClaimsPayload(token)
		if claims == nil {
			continue
		}

		// Validate Azure issuer.
		iss, ok := claims["iss"].(string)
		if !ok || !isValidAzureIssuer(iss) {
			continue
		}

		// Differentiate between access token and ID token.
		_, hasScope := claims["scp"]

		if hasScope {
			secrets = append(secrets, AzureAccessToken{Token: token})
			positions = append(positions, m[0])
		} else {
			secrets = append(secrets, AzureIdentityToken{Token: token})
			positions = append(positions, m[0])
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
