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

package veles_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

type testDetectionEngineSubCase struct {
	name  string
	input string
	want  []veles.Secret
}

// TestDetectionEngine_withSmallBuffer makes sure that the DetectionEngine
// handles retention and overlap correctly. This is best tested with small
// buffer sizes.
//
// Each test case manually ensures that retainLen is set to the maximum secret
// length.
func TestDetectionEngine_withSmallBuffer(t *testing.T) {
	fakeSecrets := velestest.FakeSecretsT(t)
	mustEngine := func(e *veles.DetectionEngine, err error) *veles.DetectionEngine {
		t.Helper()
		if err != nil {
			t.Fatalf("veles.NewDetectionEngine() error: %v, want nil", err)
		}
		return e
	}
	cases := []struct {
		name   string
		engine *veles.DetectionEngine
		sub    []testDetectionEngineSubCase
	}{
		{
			name: "single_detector",
			engine: mustEngine(veles.NewDetectionEngine(
				velestest.FakeDetectors("FOO"),
				veles.WithReadLen(5),
				veles.WithRetainLen(3),
			)),
			sub: []testDetectionEngineSubCase{
				{
					name:  "empty string",
					input: "",
					want:  nil,
				},
				{
					name:  "no matches chunk smaller retain Len",
					input: "aaa",
					want:  nil,
				},
				{
					name:  "no matches in single chunk",
					input: "aaaaaaab",
					want:  nil,
				},
				{
					name:  "no matches in multiple chunks",
					input: "aaaaaaabaaaabaaa",
					want:  nil,
				},
				{
					name:  "single match at start of single chunk",
					input: "FOOaaaab",
					want:  fakeSecrets("FOO"),
				},
				{
					name:  "single match in middle of single chunk",
					input: "aaFOOaab",
					want:  fakeSecrets("FOO"),
				},
				{
					name:  "single match at end of single chunk",
					input: "aaaaaFOO",
					want:  fakeSecrets("FOO"),
				},
				{
					name:  "single match in overlap",
					input: "aaaaaaFOOaaab",
					want:  fakeSecrets("FOO"),
				},
				{
					name:  "single match at start of second chunk",
					input: "aaaaaaabFOOab",
					want:  fakeSecrets("FOO"),
				},
				{
					name:  "single match in middle of second chunk",
					input: "aaaaaaabaFOOb",
					want:  fakeSecrets("FOO"),
				},
				{
					name:  "single match at end of second chunk",
					input: "aaaaaaabaaFOO",
					want:  fakeSecrets("FOO"),
				},
				{
					name:  "multiple matches in single chunk",
					input: "FOOFOOab",
					want:  fakeSecrets("FOO", "FOO"),
				},
				{
					name:  "multiple matches across chunks no overlap",
					input: "aaFOOaabaaFOOaab",
					want:  fakeSecrets("FOO", "FOO"),
				},
				{
					name:  "multiple matches across chunks with overlap",
					input: "aaFOOaFOOaabFOOab",
					want:  fakeSecrets("FOO", "FOO", "FOO"),
				},
			},
		},
		{
			name: "multiple_same_length_detectors",
			engine: mustEngine(veles.NewDetectionEngine(
				velestest.FakeDetectors("FOO", "BAR", "BAZ"),
				veles.WithReadLen(5),
				veles.WithRetainLen(3),
			)),
			sub: []testDetectionEngineSubCase{
				{
					name:  "empty input",
					input: "",
					want:  nil,
				},
				{
					name:  "no match",
					input: "aaaaabafsdfasdfjlasdjfalsdkjflkasdjflasdfklasjdfyhekhladsf",
					want:  nil,
				},
				{
					name:  "matches only first",
					input: "aaFOOaab",
					want:  fakeSecrets("FOO"),
				},
				{
					name:  "matches only second",
					input: "aaBARaab",
					want:  fakeSecrets("BAR"),
				},
				{
					name:  "matches only third",
					input: "aaBAZaab",
					want:  fakeSecrets("BAZ"),
				},
				{
					name:  "matches back to back",
					input: "FOOBARBAZ",
					want:  fakeSecrets("FOO", "BAR", "BAZ"),
				},
				{
					name:  "matches back to back unordered",
					input: "BAZBARFOO",
					want:  fakeSecrets("FOO", "BAR", "BAZ"),
				},
				{
					name:  "matches multiple",
					input: "aaBARBARaFOOBARaBAZaaaaBAZFOOaFOOa",
					want: fakeSecrets(
						"FOO", "FOO", "FOO",
						"BAR", "BAR", "BAR",
						"BAZ", "BAZ",
					),
				},
			},
		},
		{
			name: "multiple_different_length_detectors",
			engine: mustEngine(veles.NewDetectionEngine(
				velestest.FakeDetectors("FOO", "HELLO", "FRIENDS"),
				veles.WithRetainLen(7),
				veles.WithReadLen(5),
			)),
			sub: []testDetectionEngineSubCase{
				{
					name:  "empty input",
					input: "",
					want:  nil,
				},
				{
					name:  "no match",
					input: "ksdjlf;alksjkljfa;lsdkfukasdfjm;lasdufieuraoerwoijfdasf93423",
					want:  nil,
				},
				{
					name:  "two matches in overlap",
					input: "aaaaaFOOFOOb",
					want:  fakeSecrets("FOO", "FOO"),
				},
				{
					name:  "all match",
					input: "FOOaFRIENDSHELLOaFOOaaaaaHELLOa",
					want:  fakeSecrets("FOO", "FOO", "HELLO", "HELLO", "FRIENDS"),
				},
			},
		},
		{
			name: "overlapping_detectors",
			engine: mustEngine(veles.NewDetectionEngine(
				velestest.FakeDetectors("TEST13", "TEST1337"),
				veles.WithRetainLen(8),
				veles.WithReadLen(8),
			)),
			sub: []testDetectionEngineSubCase{
				{
					name:  "empty input",
					input: "",
					want:  nil,
				},
				{
					name:  "no match",
					input: "kjsd;aflkduyrkyerye84793248723094jhklfdslkajfahldfe7ear",
					want:  nil,
				},
				{
					name:  "matches just the smaller",
					input: "aaTEST13aaaaaaabaaa",
					want:  fakeSecrets("TEST13"),
				},
				{
					name:  "matches both",
					input: "aaTEST1337aaaaabaaTEST13aa",
					want:  fakeSecrets("TEST13", "TEST13", "TEST1337"),
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, sc := range tc.sub {
				t.Run(sc.name, func(t *testing.T) {
					t.Parallel()
					got, err := tc.engine.Detect(t.Context(), strings.NewReader(sc.input))
					if err != nil {
						t.Errorf("Detect() error: %v, want nil", err)
					}
					if diff := cmp.Diff(sc.want, got, cmpopts.EquateEmpty(), cmpopts.SortSlices(velestest.LessFakeSecretT(t))); diff != "" {
						t.Errorf("Detect() diff (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}

func TestDetectionEngine_withDefaults(t *testing.T) {
	engine, err := veles.NewDetectionEngine(velestest.FakeDetectors("BEGIN", "END"))
	if err != nil {
		t.Errorf("NewDetectionEngine() error: %v, want nil", err)
	}
	want := velestest.FakeSecretsT(t)("BEGIN", "END")
	cases := []struct {
		name     string
		inputLen int
	}{
		{
			name:     "1 kiB",
			inputLen: 1 * veles.KiB,
		},
		{
			name:     "1 MiB",
			inputLen: 1 * veles.MiB,
		},
		{
			name:     "1 GiB",
			inputLen: 1 * veles.GiB,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newFakeReader(tc.inputLen)
			got, err := engine.Detect(t.Context(), r)
			if err != nil {
				t.Fatalf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty(), cmpopts.SortSlices(velestest.LessFakeSecretT(t))); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetectionEngine_respectsContext(t *testing.T) {
	engine, err := veles.NewDetectionEngine(velestest.FakeDetectors("FOO"))
	if err != nil {
		t.Errorf("NewDetectionEngine() error: %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = engine.Detect(ctx, strings.NewReader("meaningless test input"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Detect() error: %v, want context.Canceled", err)
	}
}

func TestNewDetectionEngine_errors(t *testing.T) {
	cases := []struct {
		name      string
		detectors []veles.Detector
		opts      []veles.DetectionEngineOption
	}{
		{
			name:      "missing detectors",
			detectors: nil,
		},
		{
			name:      "empty detectors",
			detectors: []veles.Detector{},
		},
		{
			name:      "too small retain len",
			detectors: velestest.FakeDetectors("HELLOWORLD"),
			opts:      []veles.DetectionEngineOption{veles.WithRetainLen(3)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := veles.NewDetectionEngine(tc.detectors, tc.opts...); err == nil {
				t.Error("NewDetectionEngine() error: nil, want non-nil")
			}
		})
	}
}

// fakeReader can be used to simulate reads from arbitrarily large files.
//
// It will output "BEGINaaa...aaaEND" with number of 'a' in the middle so that
// the total length equals the configured len.
type fakeReader struct {
	size    int
	written int
}

func newFakeReader(size int) *fakeReader {
	return &fakeReader{
		size:    size,
		written: 0,
	}
}

func (r *fakeReader) Read(b []byte) (int, error) {
	n := 0
	if r.written == 0 {
		// Write "BEGIN" on first Read.
		if len(b) < 5 {
			return 0, io.ErrShortBuffer
		}
		b[0] = 'B'
		b[1] = 'E'
		b[2] = 'G'
		b[3] = 'I'
		b[4] = 'N'
		n = 5
		r.written = 5
	}
	if r.written >= r.size {
		return 0, io.EOF
	}
	remains := r.size - 3 - r.written
	for ; n < min(len(b), remains); n++ {
		b[n] = 'a'
		r.written++
	}
	if n == len(b) {
		return n, nil
	}
	// Write "END" at the end. Need to take special care for edge cases where the
	// buffer is almost full.
	if n < len(b) && r.size-r.written == 3 {
		b[n] = 'E'
		n++
		r.written++
	}
	if n < len(b) && r.size-r.written == 2 {
		b[n] = 'N'
		n++
		r.written++
	}
	if n < len(b) && r.size-r.written == 1 {
		b[n] = 'D'
		n++
		r.written++
	}
	return n, nil
}
