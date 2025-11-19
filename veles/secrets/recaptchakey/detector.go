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
	"slices"

	"github.com/google/osv-scalibr/veles"
)

var (
	// inlinePattern matches a "captcha" keyword followed by "private" or "secret" and captures the associated value.
	inlinePattern = regexp.MustCompile(`(?i)captcha_?(?:private|secret)[a-zA-Z_]*['"]?\s?[:=]\s?['"]?(6[A-Za-z0-9_-]{39})\b`)
	// jsonPattern matches a json object named **captcha containing a key with private or secret in it and extracts its value
	jsonPattern = regexp.MustCompile(`captcha"\s?:\s?\{[^\{]*?(?:private|secret)[a-zA-Z_]*['"]?\s?:\s?['"]?(6[A-Za-z0-9_-]{39})\b`)
	// yamlPattern matches a yaml object with 1 or 2 keys and extracts the private key value (this is an heuristic, but most of the time is good enough)
	yamlPattern = regexp.MustCompile(`captcha:\s*(?:(?:public[a-zA-Z_]*:\s?)['"]?(?:6[A-Za-z0-9_-]{39})\b\s*)?(?:private|secret)[a-zA-Z_]*\s?:\s?['"]?(6[A-Za-z0-9_-]{39})\b`)
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
	matches := slices.Concat(
		inlinePattern.FindAllSubmatchIndex(data, -1),
		jsonPattern.FindAllSubmatchIndex(data, -1),
		yamlPattern.FindAllSubmatchIndex(data, -1),
	)
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
