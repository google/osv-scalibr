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

package codeserver

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantVulns bool
	}{

		{
			name:      "auth_disabled_returns_vuln",
			handler:   validHandler(t, false),
			wantVulns: true,
		},
		{
			name:      "auth_enabled_returns_nothing",
			handler:   validHandler(t, true),
			wantVulns: false,
		},
		{
			name: "login_returns_non_200_code_returns_nothing",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			wantVulns: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			cfg := DefaultConfig()
			cfg.Remote = srv.URL

			d := New(cfg)
			invs, _ := d.Scan(t.Context(), nil, nil)

			gotVulns := len(invs.GenericFindings) > 0
			if gotVulns != tc.wantVulns {
				t.Errorf("Scan() returned unexpected vulnerabilities, got findings: %v, want findings: %v", gotVulns, tc.wantVulns)
			}
		})
	}
}

func TestScanWithTimeouts(t *testing.T) {
	tests := []struct {
		name          string
		handler       http.HandlerFunc
		expectFails   bool
		clientTimeout time.Duration
		maxDuration   time.Duration
	}{
		{
			name: "auth_staled_timeouts",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(2 * time.Second)
			},
			expectFails:   false,
			clientTimeout: 100 * time.Millisecond,
			maxDuration:   180 * time.Millisecond,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			cfg := DefaultConfig()
			cfg.Remote = srv.URL
			cfg.ClientTimeout = tc.clientTimeout

			d := New(cfg)
			start := time.Now()
			invs, err := d.Scan(t.Context(), nil, nil)
			end := time.Now()

			if tc.expectFails != (err != nil) {
				t.Errorf("Scan() unexpected error, got: %v", err)
			}

			if len(invs.GenericFindings) != 0 {
				t.Errorf("Scan() returned unexpected findings, got: %v, want nothing", invs)
			}

			if end.Sub(start) > tc.maxDuration {
				t.Errorf("Scan() took too long: %v", end.Sub(start))
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		wantURL string
	}{
		{
			name:    "darwin",
			goos:    "darwin",
			wantURL: "http://localhost:49363",
		},
		{
			name:    "linux",
			goos:    "linux",
			wantURL: "http://127.0.0.2:49363",
		},
		{
			name:    "windows",
			goos:    "windows",
			wantURL: "http://127.0.0.2:49363",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultConfigWithOS(tc.goos)
			if cfg.Remote != tc.wantURL {
				t.Errorf("defaultConfigWithOS(%q).Remote = %q, want %q", tc.goos, cfg.Remote, tc.wantURL)
			}
		})
	}
}

// validHandler returns a valid handler that will emulate the Code-Server instance. Does not emulate
// the redirection.
func validHandler(t *testing.T, authEnabled bool) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		if authEnabled {
			fmt.Fprintln(w, loadTestFile(t, "testdata/auth_enabled.html"))
			return
		}
		fmt.Fprintln(w, loadTestFile(t, "testdata/auth_disabled.html"))
	}
}

func loadTestFile(t *testing.T, filename string) string {
	t.Helper()
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("failed to open %s: %v", filename, err)
	}

	content, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("failed to read %s: %v", filename, err)
	}

	return string(content)
}
