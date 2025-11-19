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

package recaptchakey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

var (
	// secretPattern matches a "captcha" keyword followed by "private" or "secret" and captures the associated value.
	// It handles optional characters like spaces, colons, equals signs, underscores, and quotes.
	secretPattern = regexp.MustCompile(`(?i)captcha\s?[:=]?\s*_?(?:private|secret)[a-zA-Z_]*\s?[:=]\s?['"]?(6[A-Za-z0-9_-]{39})\b`)
)

const (
	maxSecretLen = 40
	maxLen       = maxSecretLen + 100 // add space for context
)

type Detector struct{}

// NewDetector returns a new Veles Detector that finds reCAPTCHA secret keys
func NewDetector() veles.Detector {
	return &Detector{}
}

// Detect implements veles.Detector.
func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	matches := secretPattern.FindAllSubmatchIndex(data, -1)
	secrets, pos := []veles.Secret{}, []int{}
	for _, match := range matches {
		if len(match) >= 4 && match[2] != -1 && match[3] != -1 {
			start := match[2]
			end := match[3]
			secrets = append(secrets, Key{Secret: string(data[start:end])})
			pos = append(pos, start)
		}
	}
	return secrets, pos
}

// MaxSecretLen implements veles.Detector.
func (d *Detector) MaxSecretLen() uint32 {
	return maxLen
}
