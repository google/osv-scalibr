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

package pgpass_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/pgpass"
)

const (
	testEntry                    = `hostname:234:database:username:password`
	testEntryWithSemicolumnInPwd = `hostname:31337:database:username:passw\:ord`
	testEntryWiwthWildcardInside = `*:*:*:*:password`
)

// TestDetector_truePositives tests for cases where we know the Detector
// will find a valid pgpass entry.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{pgpass.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testEntry,
		want: []veles.Secret{
			pgpass.Pgpass{Entry: testEntry},
		},
	}, {
		name:  "multiple matches",
		input: testEntry + "\n" + testEntry + "\n" + testEntry,
		want: []veles.Secret{
			pgpass.Pgpass{Entry: testEntry},
			pgpass.Pgpass{Entry: testEntry},
			pgpass.Pgpass{Entry: testEntry},
		},
	}, {
		name:  "match with : in pwd",
		input: testEntryWithSemicolumnInPwd,
		want: []veles.Secret{
			pgpass.Pgpass{Entry: testEntryWithSemicolumnInPwd},
		},
	}, {
		name:  "match fields with wildcard",
		input: testEntryWiwthWildcardInside,
		want: []veles.Secret{
			pgpass.Pgpass{Entry: testEntryWiwthWildcardInside},
		},
	}}
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a valid pgpass entry.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{pgpass.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty input",
		input: "",
	}, {
		name:  "malformed entry: less number of fields",
		input: `hostname:123:database:password`,
	}, {
		name:  "malformed entry: more number of fields",
		input: `hostname:1234:database:username:password:extrafield`,
	}, {
		name:  "malformed entry: invalid port number",
		input: `hostname:12343333:database:username:password`,
	}, {
		name:  "malformed entry: port field with text chars",
		input: `hostname:port:database:username:password`,
	}, {
		name:  "malformed entry: escaped: in database field",
		input: `hostname:123:data\:base:username:password`,
	}, {
		name:  "malformed entry: wildcard in password",
		input: `hostname:123:database:username:*`,
	}}
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
