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

package onepasswordkeys

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewSecretKeyDetector()
	_ veles.Detector = NewServiceTokenDetector()
	_ veles.Detector = NewRecoveryTokenDetector()
)

const (
	secretKeyMaxLen     = 64
	serviceTokenMaxLen  = 300
	recoveryTokenMaxLen = 69
)

// secretKeyRe matches 1Password Secret Keys in the format:
// A3-<6 alphanum>-<11 alphanum OR 6 alphanum-5 alphanum>-<5 alphanum group x3>
var secretKeyRe = regexp.MustCompile(`A3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`)

// serviceTokenRe matches 1Password Service Account Tokens, which:
// - Start with "ops_eyJ"
// - Followed by at least 250 base64 characters (a-zA-Z0-9+/)
// - Optionally end with up to 3 '=' padding characters
var serviceTokenRe = regexp.MustCompile(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`)

// recoveryTokenRe matches 1Password Recovery Keys in the format:
// - Start with "1PRK"
// - Followed by 13 groups of 4 alphanum characters, each separated by '-'
var recoveryTokenRe = regexp.MustCompile(`1PRK(?:-[A-Z0-9]{4}){13}`)

// NewSecretKeyDetector returns a detector for 1Password Secret Keys.
func NewSecretKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: secretKeyMaxLen,
		Re:     secretKeyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return OnePasswordSecretKey{Key: string(b)}, true
		},
	}
}

// NewServiceTokenDetector returns a detector for 1Password Service Account Tokens.
func NewServiceTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: serviceTokenMaxLen,
		Re:     serviceTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return OnePasswordServiceToken{Key: string(b)}, true
		},
	}
}

// NewRecoveryTokenDetector returns a detector for 1Password Recovery Keys.
func NewRecoveryTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: recoveryTokenMaxLen,
		Re:     recoveryTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return OnePasswordRecoveryCode{Key: string(b)}, true
		},
	}
}
