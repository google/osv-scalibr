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

package hashicorpvault

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

const (
	// maxTokenLength is the maximum size of a Vault token.
	maxTokenLength = 200
	// maxUUIDLength is the maximum size of a UUID (AppRole credential).
	maxUUIDLength = 36
	// maxContextLength is the maximum allowed distance between context and the secret
	maxContextLength = 50
	// TODO: write this better
)

// vaultTokenRe is a regular expression that matches HashiCorp Vault tokens.
// Vault tokens can start with older prefixes (s., b., r.) or newer prefixes (hvs., hvb.) followed by base64-like characters.
var vaultTokenRe = regexp.MustCompile(`(?:hv[sb]|[sbr])\.[A-Za-z0-9_-]{24,}`)

// appRoleRoleIDContextRe matches potential AppRole credential with context labels.
// This matches patterns like "role_id: uuid"
var appRoleRoleIDContextRe = regexp.MustCompile(`(?i)role_id\s*[:\s=]\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`)

// appRoleSecretIDContextRe matches potential AppRole credential with context labels.
// This matches patterns like "secret_id: uuid"
var appRoleSecretIDContextRe = regexp.MustCompile(`(?i)secret_id\s*[:\s=]\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`)

// appRoleDetector implements context-aware AppRole credential detection.
type appRoleDetector struct {
	maxUUIDLen    uint32
	maxContextLen uint32 // Maximum distance to look for context
}

// NewTokenDetector returns a new simpletoken.Detector that matches HashiCorp Vault tokens.
func NewTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     vaultTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return Token{Token: string(b)}, true
		},
	}
}

// NewAppRoleDetector returns a context-aware detector that matches UUID-formatted AppRole credentials.
// This detector analyzes surrounding context to identify role_id and secret_id pairs when possible,
// falling back to individual UUID detection when context is unclear.
func NewAppRoleDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxUUIDLength + maxContextLength,
		MaxDistance:   20,
		FindA:         findAllMatches(appRoleRoleIDContextRe),
		FindB:         findAllMatches(appRoleSecretIDContextRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return AppRoleCredentials{RoleID: string(p.A.Value), SecretID: string(p.B.Value)}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A == nil {
				return AppRoleCredentials{SecretID: string(p.B.Value)}, true
			}
			return AppRoleCredentials{RoleID: string(p.A.Value)}, true
		},
	}
}

// findAllMatches returns a function which finds all matches of a given regex.
func findAllMatches(re *regexp.Regexp) func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		matches := re.FindAllSubmatchIndex(data, -1)
		var results []*pair.Match
		for _, m := range matches {
			results = append(results, &pair.Match{
				Start: m[0],
				Value: data[m[2]:m[3]],
			})
		}
		return results
	}
}
