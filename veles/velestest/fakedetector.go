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

package velestest

import (
	"bytes"

	"github.com/google/osv-scalibr/veles"
)

var _ veles.Detector = &FakeDetector{}

// FakeDetector is a veles.Detector that finds all occurrences of a specific
// Hotword and returns corresponding instances of FakeStringSecret.
type FakeDetector struct {
	Hotword []byte
}

// NewFakeDetector creates a new FakeDetector using the given hotword.
func NewFakeDetector(hotword string) *FakeDetector {
	return &FakeDetector{Hotword: []byte(hotword)}
}

// MaxSecretLen returns the maximum length a secret found by the Detector can
// have.
func (d *FakeDetector) MaxSecretLen() uint32 {
	return uint32(len(d.Hotword))
}

// Detect finds instances of the Hotword in data and returns corresponding
// FakeStringSecrets alongside the starting positions of the matches.
func (d *FakeDetector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int
	offset := 0
	p := bytes.Index(data[offset:], d.Hotword)
	for p != -1 {
		secrets = append(secrets, NewFakeStringSecret(string(d.Hotword)))
		positions = append(positions, offset+p)
		offset += p + len(d.Hotword)
		p = bytes.Index(data[offset:], d.Hotword)
	}
	return secrets, positions
}

// FakeDetectors creates a slice of FakeDetectors each with a separate hotword
// from hotwords.
func FakeDetectors(hotwords ...string) []veles.Detector {
	var ds []veles.Detector
	for _, hotword := range hotwords {
		ds = append(ds, NewFakeDetector(hotword))
	}
	return ds
}
