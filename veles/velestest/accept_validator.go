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
	v                    veles.Validator[S]
	vWithBrokenTransport veles.Validator[S]

	trueNegatives []S
	malformed     []S

	withoutOnline bool
}

type AcceptValidatorOption[S veles.Secret] func(*testConfig[S])

var BrokenClient = newBrokenTCPClient()

func newBrokenTCPClient() *http.Client {
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

// WithBrokenTransport is used to verify the validator functionality when there are network errors.
func WithBrokenTransport[S veles.Secret](v veles.Validator[S]) AcceptValidatorOption[S] {
	return func(cfg *testConfig[S]) {
		cfg.vWithBrokenTransport = v
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

// AcceptValidator is an acceptance test for Veles Detector implementations.
func AcceptValidator[S veles.Secret](t *testing.T, v veles.Validator[S], opts ...AcceptValidatorOption[S]) {
	t.Helper()

	cfg := &testConfig[S]{
		v: v,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// At least one sample secret is needed to test context cancellation and transport errors.
	var sampleSecret S
	hasSample := false
	if len(cfg.trueNegatives) > 0 {
		sampleSecret = cfg.trueNegatives[0]
		hasSample = true
	} else if len(cfg.malformed) > 0 {
		sampleSecret = cfg.malformed[0]
		hasSample = true
	}

	if !hasSample {
		t.Fatal("AcceptValidator requires at least one test secret. Use WithTrueNegatives or WithMalformedSecrets.")
	}

	t.Run("cancelled-ctx", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		status, err := cfg.v.Validate(ctx, sampleSecret)
		if status != veles.ValidationFailed {
			t.Errorf("Validate() with cancelled context returned status %v, want %v", status, veles.ValidationFailed)
		}
		if err == nil {
			t.Fatal("Validate() with cancelled context returned nil error, want non-nil error")
		}
	})

	t.Run("unreachable-service", func(t *testing.T) {
		if cfg.vWithBrokenTransport == nil {
			t.Skip("No client with broken Transport provided")
		}

		status, err := cfg.vWithBrokenTransport.Validate(t.Context(), sampleSecret)
		if status != veles.ValidationFailed {
			t.Errorf("Validate() with unreachable service returned status %v, want %v", status, veles.ValidationFailed)
		}
		if err == nil {
			t.Fatal("Validate() with unreachable service returned nil error, want non-nil error")
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
}
