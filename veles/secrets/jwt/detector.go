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

package jwt

import (
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/jwt"
)

type detector struct{}

// NewDetector returns a new Veles Detector that finds JWT tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

// Detect finds JWT tokens.
func (d *detector) Detect(data []byte) ([]veles.Secret, []int) {
	tokens, positions := jwt.ExtractTokens(data)
	secrets := make([]veles.Secret, len(tokens))
	for i, t := range tokens {
		secrets[i] = Token{Value: t.Raw()}
	}
	return secrets, positions
}

// MaxSecretLen return the max length that a JWT token can have.
func (d *detector) MaxSecretLen() uint32 {
	return jwt.MaxTokenLength
}
