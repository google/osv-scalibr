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

package secrets_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestFileRequired(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty",
			path: "",
			want: false,
		},
		{
			name: "accept JSON",
			path: "foo.json",
			want: true,
		},
		{
			name: "accept YAML",
			path: "bar.yaml",
			want: true,
		},
		{
			name: "accept CFG",
			path: "baz.cfg",
			want: true,
		},
		{
			name: "accept textproto",
			path: "hello.textproto",
			want: true,
		},
		{
			name: "accepts full path",
			path: "/foo/bar/baz/credentials.json",
			want: true,
		},
		{
			name: "accepts last of multiple extensions",
			path: "credentials.enc.json",
			want: true,
		},
		{
			name: "accepts uppercase",
			path: "credentials.JSON",
			want: true,
		},
		{
			name: "accepts mixed case",
			path: "credentials.Json",
			want: true,
		},
		{
			name: "rejects e.g. PNG",
			path: "image.png",
			want: false,
		},
		{
			name: "rejects if not last in multiple extensions",
			path: "credentials.json.tar.gz",
			want: false,
		},
		{
			name: "rejects w/o extension",
			path: "/foo/bar/baz",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := secrets.New()
			if got := e.FileRequired(simplefileapi.New(tc.path, nil)); got != tc.want {
				t.Errorf("FileRequired(%q) = %t, want %t", tc.path, got, tc.want)
			}
		})
	}
}

// TestExtract tests that the Extractor produces the correct output based on the
// Veles library.
// Dedicated tests for specific credentials exist in the Veles library.
func TestExtract(t *testing.T) {
	path := "/foo/bar/baz.json"
	less := func(a, b *inventory.Secret) bool {
		return velestest.LessFakeSecretT(t)(a.Secret, b.Secret)
	}
	cases := []struct {
		name      string
		detectors []veles.Detector
		input     string
		want      []*inventory.Secret
	}{
		{
			name:      "empty input",
			detectors: velestest.FakeDetectors("FOO"),
			input:     "",
			want:      nil,
		},
		{
			name:      "single match",
			detectors: velestest.FakeDetectors("FOO"),
			input:     "Hello, world! FOO BAR BAZ!",
			want: []*inventory.Secret{
				{
					Secret:   velestest.NewFakeStringSecret("FOO"),
					Location: path,
				},
			},
		},
		{
			name:      "multiple matches",
			detectors: velestest.FakeDetectors("FOO"),
			input:     "Hello FOO! FOO BAR BAZ!",
			want: []*inventory.Secret{
				{
					Secret:   velestest.NewFakeStringSecret("FOO"),
					Location: path,
				},
				{
					Secret:   velestest.NewFakeStringSecret("FOO"),
					Location: path,
				},
			},
		},
		{
			name:      "multiple matches from different detectors",
			detectors: velestest.FakeDetectors("FOO", "BAR"),
			input:     "Hello FOO! FOO BAR BAZ!",
			want: []*inventory.Secret{
				{
					Secret:   velestest.NewFakeStringSecret("FOO"),
					Location: path,
				},
				{
					Secret:   velestest.NewFakeStringSecret("FOO"),
					Location: path,
				},
				{
					Secret:   velestest.NewFakeStringSecret("BAR"),
					Location: path,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := veles.NewDetectionEngine(tc.detectors)
			if err != nil {
				t.Fatalf("veles.NewDetectionEngine() err: %v", err)
			}
			e := secrets.NewWithEngine(engine)
			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS("."),
				Path:   path,
				Reader: strings.NewReader(tc.input),
			}
			gotInv, err := e.Extract(t.Context(), input)
			if err != nil {
				t.Errorf("Extract() err=%v, want nil", err)
			}
			if len(gotInv.Packages) > 0 || len(gotInv.Findings) > 0 {
				t.Errorf("Extract() got inventory other than secrets: %v", gotInv)
			}
			got := gotInv.Secrets
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty(), cmpopts.SortSlices(less)); diff != "" {
				t.Errorf("Extract() diff (-want +got):\n%s", diff)
			}
		})
	}
}
