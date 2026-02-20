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

package ntuple_test

import (
	"bytes"
	"math/rand"
	"regexp"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

func setupTestDetector() *ntuple.Detector {
	r1 := regexp.MustCompile(`https://api\.example\.com/v[1-9]`)
	r2 := regexp.MustCompile(`client_id-[a-zA-Z0-9]{10}`)
	r3 := regexp.MustCompile(`secret-[a-zA-Z0-9]{20}`)

	return &ntuple.Detector{
		MaxDistance:   200,
		MaxElementLen: 50,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(r1),
			ntuple.FindAllMatches(r2),
			ntuple.FindAllMatches(r3),
		},
		FromTuple: func(m []ntuple.Match) (veles.Secret, bool) {
			return nil, true
		},
	}
}

// generatePayload creates a byte buffer of `size` and injects matches
// every `density` bytes to simulate different loads.
func generatePayload(size, density int) []byte {
	buf := bytes.Repeat([]byte("some random noise padding data "), size/30+1)
	buf = buf[:size]

	// Use a fixed seed for deterministic benchmark runs
	rng := rand.New(rand.NewSource(42))

	tokens := [][]byte{
		[]byte("https://api.example.com/v1"),
		[]byte("client_id-ABCDEFGHIJ"),
		[]byte("secret-ABCDEFGHIJKLMNOPQRST"),
	}

	for i := 0; i < size-50; i += density {
		// Pick a random token from our 3 finders
		token := tokens[rng.Intn(len(tokens))]
		copy(buf[i:], token)
	}

	return buf
}

// BenchmarkDetector evaluates the performance of the nutple detectors across files of varying sizes and secret densities.
//
// launch using:
//
//	```
//	make test_bench
//	```
func BenchmarkDetector(b *testing.B) {
	detector := setupTestDetector()

	b.Run("Sparse_100KB", func(b *testing.B) {
		// 100KB payload, injecting a regex match roughly every 5000 bytes.
		// This simulates standard source code or config files.
		payload := generatePayload(100*1024, 5000)
		b.ResetTimer()

		for b.Loop() {
			detector.Detect(payload)
		}
	})

	b.Run("Dense_100KB", func(b *testing.B) {
		// 100KB payload, injecting a regex match roughly every 300 bytes.
		// This creates heavy combinatorial pressure on `generateTuples`
		// and the DP algorithm in `selectTuples`.
		payload := generatePayload(100*1024, 300)
		b.ResetTimer()

		for b.Loop() {
			detector.Detect(payload)
		}
	})

	b.Run("Extreme_1MB", func(b *testing.B) {
		// 1MB payload with a moderate density.
		payload := generatePayload(1024*1024, 1000)
		b.ResetTimer()

		for b.Loop() {
			detector.Detect(payload)
		}
	})
}
