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

package velestest

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
)

const (
	// DefaultPad is the default padding character to use when adding text before
	// or after a candidate secret.
	DefaultPad rune = ' '
)

// AcceptDetectorOption allows to configure the acceptance test in special cases
// e.g. to set a special padding character.
type AcceptDetectorOption func(*acceptDetectorRunner)

// WithPad overrides the DefaultPad character for the acceptance test.
// This is the character that's repeated to fill text before or after a secret
// in the tests.
func WithPad(pad rune) AcceptDetectorOption {
	return func(r *acceptDetectorRunner) {
		r.pad = string(pad)
	}
}

// WithBackToBack enables acceptance tests that check that secrets are even
// found when they are not otherwise delimited.
//
// E.g. a Detector that finds exactly the string "foo" would also find two
// instances in "foofoo".
func WithBackToBack() AcceptDetectorOption {
	return func(r *acceptDetectorRunner) {
		r.backToBack = true
	}
}

// AcceptDetector is an acceptance test for Veles Detector implementations.
// All implementations are expected to run this as part of their unit tests.
// In addition, all Detectors should also test specific behaviors in dedicated
// unit tests by utilizing a veles.DetectionEngine initialized with only the
// specific Detector.
//
// The idea is to give it a minimal, true positive example that exercises the
// Detector's matching logic.
func AcceptDetector(t *testing.T, d veles.Detector, example string, secret veles.Secret, opts ...AcceptDetectorOption) {
	t.Helper()
	r := acceptDetectorRunner{
		d:       d,
		example: example,
		secret:  secret,
		pad:     string(DefaultPad),
	}
	for _, opt := range opts {
		opt(&r)
	}
	t.Run("positions", r.testPositions)
	t.Run("engine", r.testEngine)
	t.Run("max-secret-len", r.testMaxSecretLen)
}

type acceptDetectorRunner struct {
	d          veles.Detector
	example    string
	secret     veles.Secret
	pad        string
	backToBack bool
}

func (r acceptDetectorRunner) padInput(s string, pre int, post int) string {
	return strings.Repeat(r.pad, pre) + s + strings.Repeat(r.pad, post)
}

func (r acceptDetectorRunner) testPositions(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantSecrets []veles.Secret
		wantPos     []int
	}{
		{
			name: "empty input does not match",
		},
		{
			name:        "matches exact",
			input:       r.example,
			wantSecrets: []veles.Secret{r.secret},
			wantPos:     []int{0},
		},
		{
			name:        "matches at the start",
			input:       r.padInput(r.example, 0, 31),
			wantSecrets: []veles.Secret{r.secret},
			wantPos:     []int{0},
		},
		{
			name:        "matches at the end",
			input:       r.padInput(r.example, 13, 0),
			wantSecrets: []veles.Secret{r.secret},
			wantPos:     []int{13},
		},
		{
			name:        "matches in the middle",
			input:       r.padInput(r.example, 17, 31),
			wantSecrets: []veles.Secret{r.secret},
			wantPos:     []int{17},
		},
		{
			name:        "matches multiple",
			input:       r.padInput(r.example, 13, 42) + r.example + r.padInput(r.example, 69, 31),
			wantSecrets: []veles.Secret{r.secret, r.secret, r.secret},
			wantPos: []int{
				13,
				13 + 42 + len(r.example),
				13 + 42 + 69 + 2*len(r.example),
			},
		},
	}
	if r.backToBack {
		cases = append(cases, struct {
			name        string
			input       string
			wantSecrets []veles.Secret
			wantPos     []int
		}{
			name:        "matches back to back",
			input:       r.example + r.example,
			wantSecrets: []veles.Secret{r.secret, r.secret},
			wantPos:     []int{0, len(r.example)},
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotSecrets, gotPositions := r.d.Detect([]byte(tc.input))
			// There is no requirement that the secrets have to be returned in order as long as they correspond to their positions.
			// However, since we're only testing _the same_ secret here, we're not testing that behavior.
			if diff := cmp.Diff(tc.wantSecrets, gotSecrets, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() secrets diff (-want +got):\n%s", diff)
			}
			// There is no requirement that the positions have to be returned in order!
			if diff := cmp.Diff(tc.wantPos, gotPositions, cmpopts.EquateEmpty(), cmpopts.SortSlices(func(a, b int) bool { return a < b })); diff != "" {
				t.Errorf("Detect() positions diff (-want +got):\n%s", diff)
			}
		})
	}
}

func (r acceptDetectorRunner) testEngine(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{r.d})
	if err != nil {
		t.Fatalf("veles.NewDetectionEngine() error: %v", err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "empty input does not match",
		},
		{
			name:  "matches exact",
			input: r.example,
			want:  []veles.Secret{r.secret},
		},
		{
			name:  "matches at the start",
			input: r.padInput(r.example, 0, 31),
			want:  []veles.Secret{r.secret},
		},
		{
			name:  "matches at the end",
			input: r.padInput(r.example, 13, 0),
			want:  []veles.Secret{r.secret},
		},
		{
			name:  "matches in the middle",
			input: r.padInput(r.example, 17, 31),
			want:  []veles.Secret{r.secret},
		},
		{
			name:  "matches multiple",
			input: r.padInput(r.example, 13, 42) + r.example + r.padInput(r.example, 69, 31),
			want:  []veles.Secret{r.secret, r.secret, r.secret},
		},
		{
			name:  "matches with large padding",
			input: r.padInput(r.example, 256*veles.KiB, 128*veles.KiB),
			want:  []veles.Secret{r.secret},
		},
	}
	if r.backToBack {
		cases = append(cases, struct {
			name  string
			input string
			want  []veles.Secret
		}{
			name:  "matches back to back",
			input: r.example + r.example,
			want:  []veles.Secret{r.secret, r.secret},
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v", err)
			}
			// The engine is under no obligation to return the secrets in a specific order.
			// However since we're testing only with the same secret, we don't need to account for that.
			// Also, the engine has no way to compare secrets for equality so we expect redundant results, even in the same stream.
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// testMaxSecretLen assures that the value the Detector gives for MaxSecretLen
// is actually enough to find secrets.
// This is by no means comprehensive as MaxSecretLen (as the name suggests) is a
// maximum so secrets can be shorter.
// However it functions as a spot check to ensure that if only this value were
// used, at least the example could be found. If it couldn't, we'd know that
// something is broken.
func (r acceptDetectorRunner) testMaxSecretLen(t *testing.T) {
	readLen := uint32(veles.KiB)
	if r.d.MaxSecretLen() > readLen {
		readLen = 2 * r.d.MaxSecretLen() // some space otherwise read = retain
	}
	retainLen := r.d.MaxSecretLen()
	e, err := veles.NewDetectionEngine(
		[]veles.Detector{r.d},
		veles.WithReadLen(readLen),
		veles.WithRetainLen(retainLen),
	)
	if err != nil {
		t.Fatalf("veles.NewDetectionEngine(d, %d, %d) error: %v", readLen, retainLen, err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "end of chunk",
			input: r.padInput(r.example, int(readLen)-len(r.example)-1, 42),
			want:  []veles.Secret{r.secret},
		},
		{
			name:  "start of next chunk",
			input: r.padInput(r.example, int(readLen), 42),
			want:  []veles.Secret{r.secret},
		},
		{
			name:  "in the overlap",
			input: r.padInput(r.example, int(readLen)-len(r.example)/2, 42),
			want:  []veles.Secret{r.secret},
		},
		{
			name:  "multiple at edge with padding",
			input: r.padInput(r.example+r.pad+r.example+r.pad+r.example, int(readLen)-len(r.example)-3, 42),
			want:  []veles.Secret{r.secret, r.secret, r.secret},
		},
	}
	if r.backToBack {
		cases = append(cases, struct {
			name  string
			input string
			want  []veles.Secret
		}{
			name:  "multiple at edge back to back",
			input: r.padInput(r.example+r.example+r.example, int(readLen)-len(r.example)-3, 42),
			want:  []veles.Secret{r.secret, r.secret, r.secret},
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
