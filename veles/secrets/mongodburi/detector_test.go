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

package mongodbconnectionurl_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	mongodburi "github.com/google/osv-scalibr/veles/secrets/mongodburi"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testURL = `mongodb://myDatabaseUser:D1fficultP%40ssw0rd@localhost`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		mongodburi.NewDetector(),
		testURL,
		mongodburi.MongoDBConnectionURL{URL: testURL},
		velestest.WithPad(' '),
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a MongoDB connection URL/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mongodburi.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	testURLWithPort := "mongodb://myDatabaseUser:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin"
	testURLSRV := "mongodb+srv://myUser:myPass@cluster0.example.net/myDB?retryWrites=true"

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching URL",
		input: testURL,
		want: []veles.Secret{
			mongodburi.MongoDBConnectionURL{URL: testURL},
		},
	}, {
		name:  "URL with port and options",
		input: testURLWithPort,
		want: []veles.Secret{
			mongodburi.MongoDBConnectionURL{URL: testURLWithPort},
		},
	}, {
		name:  "mongodb+srv scheme",
		input: testURLSRV,
		want: []veles.Secret{
			mongodburi.MongoDBConnectionURL{URL: testURLSRV},
		},
	}, {
		name:  "match at end of string",
		input: `MONGO_URI=` + testURL,
		want: []veles.Secret{
			mongodburi.MongoDBConnectionURL{URL: testURL},
		},
	}, {
		name:  "match in middle of string",
		input: `MONGO_URI="` + testURL + `"`,
		want: []veles.Secret{
			// The trailing quote is consumed by [^\s]+ but that's fine;
			// the URL is still detected.
			mongodburi.MongoDBConnectionURL{URL: testURL + `"`},
		},
	}, {
		name:  "multiple matches on separate lines",
		input: testURL + "\n" + testURLWithPort,
		want: []veles.Secret{
			mongodburi.MongoDBConnectionURL{URL: testURL},
			mongodburi.MongoDBConnectionURL{URL: testURLWithPort},
		},
	}, {
		name: "larger input containing URL",
		input: fmt.Sprintf(`
# Database config
MONGO_URI=%s
DB_NAME=mydb
		`, testURL),
		want: []veles.Secret{
			mongodburi.MongoDBConnectionURL{URL: testURL},
		},
	}, {
		name:  "URL with numeric password",
		input: "mongodb://admin:123456@db.example.com:27017",
		want: []veles.Secret{
			mongodburi.MongoDBConnectionURL{URL: "mongodb://admin:123456@db.example.com:27017"},
		},
	}, {
		name:  "URL with special chars in password (percent-encoded)",
		input: "mongodb://user:p%40ss%3Aw0rd@host.example.com:27017/testdb",
		want: []veles.Secret{
			mongodburi.MongoDBConnectionURL{URL: "mongodb://user:p%40ss%3Aw0rd@host.example.com:27017/testdb"},
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
// will not find a MongoDB connection URL.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mongodburi.NewDetector()})
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
		name:  "mongodb URL without credentials",
		input: "mongodb://localhost:27017/mydb",
	}, {
		name:  "mongodb URL with only username (no password)",
		input: "mongodb://user@localhost:27017",
	}, {
		name:  "random text",
		input: "this is just some random text without any mongodb urls",
	}, {
		name:  "http URL should not match",
		input: "http://user:pass@example.com",
	}, {
		name:  "incomplete scheme",
		input: "mongo://user:pass@localhost",
	}, {
		name:  "missing host after @",
		input: "mongodb://user:pass@",
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
