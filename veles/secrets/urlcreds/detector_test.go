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

package urlcreds_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	mongodburi "github.com/google/osv-scalibr/veles/secrets/mongodburl"
	"github.com/google/osv-scalibr/veles/secrets/urlcreds"
)

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{urlcreds.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "simple_matching_string",
			input: "http://user:password@example.com",
			want: []veles.Secret{
				urlcreds.Credentials{FullURL: "http://user:password@example.com"},
			},
		},
		{
			name:  "user_no_password",
			input: "http://user:@example.com",
			want: []veles.Secret{
				urlcreds.Credentials{FullURL: "http://user:@example.com"},
			},
		},
		{
			name:  "password_no_user",
			input: "http://:password@example.com",
			want: []veles.Secret{
				urlcreds.Credentials{FullURL: "http://:password@example.com"},
			},
		},
		{
			name:  "encoded_user_and_password",
			input: "http://user%40name:pass%3Aword@example.com",
			want: []veles.Secret{
				urlcreds.Credentials{FullURL: "http://user%40name:pass%3Aword@example.com"},
			},
		},
		{
			name:  "encoded_user_no_password",
			input: "http://user%40name:@example.com",
			want: []veles.Secret{
				urlcreds.Credentials{FullURL: "http://user%40name:@example.com"},
			},
		},
		{
			name:  "encoded_password_no_user",
			input: "http://:pass%3Aword@example.com",
			want: []veles.Secret{
				urlcreds.Credentials{FullURL: "http://:pass%3Aword@example.com"},
			},
		},
		{
			name:  "mongodb_url_returns_MongoDBConnectionURL",
			input: "mongodb://myUser:myPass@localhost",
			want: []veles.Secret{
				mongodburi.MongoDBConnectionURL{URL: "mongodb://myUser:myPass@localhost"},
			},
		},
		{
			name:  "mongodb_url_with_port_and_options",
			input: "mongodb://myUser:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin",
			want: []veles.Secret{
				mongodburi.MongoDBConnectionURL{URL: "mongodb://myUser:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin"},
			},
		},
		{
			name:  "mongodb_srv_url_returns_MongoDBConnectionURL",
			input: "mongodb+srv://myUser:myPass@cluster0.example.net/myDB?retryWrites=true",
			want: []veles.Secret{
				mongodburi.MongoDBConnectionURL{URL: "mongodb+srv://myUser:myPass@cluster0.example.net/myDB?retryWrites=true"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{urlcreds.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
		},
		{
			name:  "no_userinfo",
			input: "http://example.com",
		},
		{
			name:  "no_userinfo_strange",
			input: "https://example.com?email=user@gmail.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
