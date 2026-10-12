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
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/google/osv-scalibr/veles"
)

type testConfig[S veles.Secret] struct {
	v                   veles.Validator[S]
	withBrokenTransport func(veles.Validator[S]) bool

	trueNegatives []S
	malformed     []S

	withoutOnline bool
}

// AcceptValidatorOption allows to configure the acceptance test
type AcceptValidatorOption[S veles.Secret] func(*testConfig[S])

// BrokenClient is an http.Client that simulates a network failure ("connection refused") on any dial attempt.
// Pass it to a WithBrokenTransport callback to verify that a Validator returns
// veles.ValidationFailed on network error.
var BrokenClient = newBrokenClient()

func newBrokenClient() *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, &net.OpError{
				Op:  "dial",
				Net: network,
				Err: errors.New("simulated connection refused"),
			}
		},
	}

	return &http.Client{
		Transport: transport,
	}
}

// WithBrokenTransport configures the validator for the unreachable-service check.
// The callback receives the same validator passed to AcceptValidator and runs after
// the other checks, so it can replace the validator's client with BrokenClient.
func WithBrokenTransport[S veles.Secret, V veles.Validator[S]](configure func(V)) AcceptValidatorOption[S] {
	return func(cfg *testConfig[S]) {
		cfg.withBrokenTransport = func(v veles.Validator[S]) bool {
			validator, ok := v.(V)
			if ok {
				configure(validator)
			}
			return ok
		}
	}
}

// WithTrueNegatives provides secrets that are perfectly formatted (including metadata)
// but contain fake credentials. They are expected to return veles.ValidationInvalid.
func WithTrueNegatives[S veles.Secret](secrets ...S) AcceptValidatorOption[S] {
	return func(cfg *testConfig[S]) {
		cfg.trueNegatives = append(cfg.trueNegatives, secrets...)
	}
}

// WithMalformedSecrets provides secrets that have invalid formats, missing metadata,
// or broken local constraints. They are expected to return veles.ValidationFailed.
func WithMalformedSecrets[S veles.Secret](secrets ...S) AcceptValidatorOption[S] {
	return func(cfg *testConfig[S]) {
		cfg.malformed = append(cfg.malformed, secrets...)
	}
}

// WithoutOnline disables online testing.
func WithoutOnline[S veles.Secret]() AcceptValidatorOption[S] {
	return func(cfg *testConfig[S]) {
		cfg.withoutOnline = true
	}
}

// AcceptValidator is an acceptance test for Veles Validator implementations.
func AcceptValidator[S veles.Secret](t *testing.T, v veles.Validator[S], opts ...AcceptValidatorOption[S]) {
	t.Helper()

	cfg := &testConfig[S]{
		v: v,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// At least one sample secret is needed to test context cancellation and transport errors.
	if len(cfg.trueNegatives) == 0 {
		t.Fatal("AcceptValidator requires at least one test secret. Use WithTrueNegatives to provide invalid but syntactically correct secrets.")
	}
	sampleSecret := cfg.trueNegatives[0]

	// Test malformed secrets
	t.Run("cancelled-ctx", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		expected := ctx.Err()

		status, err := cfg.v.Validate(ctx, sampleSecret)
		if status != veles.ValidationFailed {
			t.Errorf("Validate() with cancelled context returned status %v, want %v", status, veles.ValidationFailed)
		}
		if !errors.Is(err, expected) {
			t.Errorf("Validate() with cancelled context returned error: %v, want: %v", err, expected)
		}
	})

	// Test malformed secrets
	if len(cfg.malformed) > 0 {
		t.Run("malformed-secrets", func(t *testing.T) {
			for _, s := range cfg.malformed {
				status, err := cfg.v.Validate(t.Context(), s)
				if status != veles.ValidationFailed {
					t.Errorf("Validate() with malformed secret returned status %v, want %v", status, veles.ValidationFailed)
				}
				if err == nil {
					t.Errorf("Validate() with malformed secret returned ValidationFailed but nil error")
				}
			}
		})
	}

	// Test true negatives (invalid tokens)
	if len(cfg.trueNegatives) > 0 {
		t.Run("true-negatives", func(t *testing.T) {
			if cfg.withoutOnline {
				t.Skip("skipping Validator online as the WithoutOnline option was used")
			}
			if os.Getenv("ONLINE") == "" {
				t.Skip("skipping Validator online test, add ONLINE=1 to launch the test")
			}

			for _, s := range cfg.trueNegatives {
				status, err := cfg.v.Validate(t.Context(), s)
				if status != veles.ValidationInvalid {
					t.Errorf("Validate() with true-negative secret returned status %v, want %v", status, veles.ValidationInvalid)
				}
				if err != nil {
					t.Errorf("Validate() with true-negative secret returned unexpected error: %v", err)
				}
			}
		})
	}

	// Test the validator behaviour when a connection error happens
	if cfg.withBrokenTransport != nil {
		t.Run("unreachable-service", func(t *testing.T) {
			if !cfg.withBrokenTransport(cfg.v) {
				t.Fatal("WithBrokenTransport callback type does not match the validator")
			}

			status, err := cfg.v.Validate(t.Context(), sampleSecret)
			if status != veles.ValidationFailed {
				t.Errorf("Validate() with unreachable service returned status %v, want %v", status, veles.ValidationFailed)
			}
			if err == nil {
				t.Error("Validate() with unreachable service returned nil error, want non-nil error")
			}
		})
	}
}
