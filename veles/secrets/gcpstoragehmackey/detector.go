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

package gcpstoragehmackey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

var (
	// TODO: fill these
	accessIDPattern = regexp.MustCompile("")
	secretPattern   = regexp.MustCompile("")
)

var (
	maxAccessIDLen = 1
	maxSecretLen   = 1
	maxDistance    = 1
	maxTotalLen    = maxAccessIDLen + maxSecretLen + maxDistance
)

// Detector is a Veles Detector that findsGoogle Cloud Storage HMAC keys
type Detector struct{}

// NewDetector returns a new Veles Detector that finds Google Cloud Storage HMAC keys
func NewDetector() *Detector {
	return &Detector{}
}

// MaxSecretLen returns the maximum length a secret from this Detector can have.
func (d *Detector) MaxSecretLen() uint32 {
	return uint32(maxTotalLen)
}

// Detect finds Google Cloud Storage HMAC keys
func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	panic("unimplemented")
}
