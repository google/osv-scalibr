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

package appusertoservertoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

const tokenMaxLen = 40

var tokenPattern = regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`)

// Detector detects Github app refresh tokens
type Detector struct{}

// NewDetector returns a new Veles Detector that finds Github app refresh tokens
func NewDetector() veles.Detector {
	return Detector{}
}

// Detect detects Github app refresh tokens
func (d Detector) Detect(data []byte) ([]veles.Secret, []int) {
	secrets := []veles.Secret{}
	positions := []int{}
	for _, m := range tokenPattern.FindAllIndex(data, -1) {
		l, r := m[0], m[1]
		token := string(data[l:r])
		// TODO: add checksum validation
		secrets = append(secrets, GithubAppUserToServerToken{Token: token})
		positions = append(positions, l)
	}
	return secrets, positions
}

// MaxSecretLen return the Github App refresh token max length
func (d Detector) MaxSecretLen() uint32 {
	return tokenMaxLen
}
