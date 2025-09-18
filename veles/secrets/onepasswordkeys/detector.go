// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
)

const secretKeyMaxLen = 64

var secretKeyRe = regexp.MustCompile(`A3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`)

const serviceTokenMaxLen = 300

var serviceTokenRe = regexp.MustCompile(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`)

// NewSecretKeyDetector returns a detector for 1Password Secret Keys.
func NewSecretKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: secretKeyMaxLen,
		Re:     secretKeyRe,
		FromMatch: func(b []byte) veles.Secret {
			return OnePasswordSecretKey{Key: string(b)}
		},
	}
}

// NewServiceTokenDetector returns a detector for 1Password Service Account Tokens.
func NewServiceTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: serviceTokenMaxLen,
		Re:     serviceTokenRe,
		FromMatch: func(b []byte) veles.Secret {
			return OnePasswordServiceToken{Key: string(b)}
		},
	}
}
