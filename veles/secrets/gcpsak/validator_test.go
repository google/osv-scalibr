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

package gcpsak_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
)

const (
	pathPrefix = "/robot/v1/metadata/x509/"
)

func serveCerts(t *testing.T, certs map[string]string) http.Handler {
	t.Helper()
	data, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		t.Errorf("json.Marshal(certs) error: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(pathPrefix+exampleServiceAccount, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
	return mux
}

func TestValidator(t *testing.T) {
	exampleCerts := map[string]string{
		exampleKeyID: exampleCertificate,
	}
	// Set up fake "GCP metadata" HTTP server.
	srv := httptest.NewTLSServer(serveCerts(t, exampleCerts))
	t.Cleanup(func() {
		srv.Close()
	})
	validator := gcpsak.NewValidator(
		gcpsak.WithClient(srv.Client()),
		gcpsak.WithDefaultUniverse(srv.Listener.Addr().String()),
	)

	cases := []struct {
		name string
		sak  gcpsak.GCPSAK
		want veles.ValidationStatus
	}{
		{
			name: "example valid",
			sak: gcpsak.GCPSAK{
				PrivateKeyID:   exampleKeyID,
				ServiceAccount: exampleServiceAccount,
				Signature:      exampleSignature,
			},
			want: veles.ValidationValid,
		},
		{
			name: "unknown private key ID invalid",
			sak: gcpsak.GCPSAK{
				PrivateKeyID:   "foobar",
				ServiceAccount: exampleServiceAccount,
				Signature:      exampleSignature,
			},
			want: veles.ValidationInvalid,
		},
		{
			name: "unknown service account invalid",
			sak: gcpsak.GCPSAK{
				PrivateKeyID:   exampleKeyID,
				ServiceAccount: "unknown-account@asasdasd",
				Signature:      exampleSignature,
			},
			want: veles.ValidationInvalid,
		},
		{
			name: "invalid signature invalid",
			sak: gcpsak.GCPSAK{
				PrivateKeyID:   exampleKeyID,
				ServiceAccount: exampleServiceAccount,
				Signature:      make([]byte, 256),
			},
			want: veles.ValidationInvalid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := validator.Validate(t.Context(), tc.sak)
			if err != nil {
				t.Errorf("Validate() error: %v, want nil", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidator_errors(t *testing.T) {
	sak := gcpsak.GCPSAK{
		PrivateKeyID:   exampleKeyID,
		ServiceAccount: exampleServiceAccount,
		Signature:      exampleSignature,
	}
	cases := []struct {
		name    string
		handler http.Handler
	}{
		{
			name: "other HTTP status",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}),
		},
		{
			// This should never happen with the actual GCP metadata server.
			name: "response is not JSON",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, "JSON machine broke - understandable have a nice day")
			}),
		},
		{
			// This should never happen with the actual GCP metadata server.
			name: "certificate is not PEM",
			handler: serveCerts(t, map[string]string{
				exampleKeyID: "This doesn't even parse as a PEM block.",
			}),
		},
		{
			// This should never happen with the actual GCP metadata server.
			name: "certificate is not DER",
			handler: serveCerts(t, map[string]string{
				exampleKeyID: "-----BEGIN CERTIFICATE-----\nThis is not a real certificate.\n-----END CERTIFICATE-----\n",
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewTLSServer(tc.handler)
			t.Cleanup(func() {
				srv.Close()
			})
			validator := gcpsak.NewValidator(
				gcpsak.WithClient(srv.Client()),
				gcpsak.WithDefaultUniverse(srv.Listener.Addr().String()),
			)
			status, err := validator.Validate(t.Context(), sak)
			if err == nil {
				t.Error("Validate() error = nil, want err")
			}
			if status != veles.ValidationFailed {
				t.Errorf("Validate() = %q, want %q", status, veles.ValidationFailed)
			}
		})
	}
}

func TestValidator_respectsContext(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	t.Cleanup(func() {
		srv.Close()
	})
	validator := gcpsak.NewValidator(
		gcpsak.WithClient(srv.Client()),
		gcpsak.WithDefaultUniverse(srv.Listener.Addr().String()),
	)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sak := gcpsak.GCPSAK{
		PrivateKeyID:   exampleKeyID,
		ServiceAccount: exampleServiceAccount,
		Signature:      exampleSignature,
	}
	if _, err := validator.Validate(ctx, sak); !errors.Is(err, context.Canceled) {
		t.Errorf("Validate() error: %v, want context.Canceled", err)
	}
}
