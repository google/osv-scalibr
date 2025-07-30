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

package sdp

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"

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
			name: "accepts no extension",
			path: "baz/foo",
			want: true,
		},
		{
			name: "accepts json",
			path: "baz/foo.json",
			want: true,
		},
		{
			name: "accepts text",
			path: "foo.txt",
			want: true,
		},
		{
			name: "accepts image",
			path: "foo.jpeg",
			want: true,
		},
		{
			name: "rejects unsupported",
			path: "foo.jar",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New()
			if got := e.FileRequired(simplefileapi.New(tc.path, nil)); got != tc.want {
				t.Errorf("FileRequired(%q) = %t, want %t", tc.path, got, tc.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	cases := []struct {
		name string
		path string
		want *inventory.SensitiveData
	}{
		{
			name: "extract json",
			path: "/foo/bar/baz.json",
			want: &inventory.SensitiveData{
				Name:     "/foo/bar/baz.json",
				Location: "/foo/bar/baz.json",
				FileType: inventory.JSONFileType,
			},
		},
		{
			name: "extract textproto",
			path: "/foo/bar/test.textproto",
			want: &inventory.SensitiveData{
				Name:     "/foo/bar/test.textproto",
				Location: "/foo/bar/test.textproto",
				FileType: inventory.TextFileType,
			},
		},
		{
			name: "extract no extension",
			path: "/foo/bar/noextension",
			want: &inventory.SensitiveData{
				Name:     "/foo/bar/noextension",
				Location: "/foo/bar/noextension",
				FileType: inventory.UnknownFileType,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New()
			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS("."),
				Path:   tc.path,
				Reader: strings.NewReader("dummy content"),
			}
			gotInv, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract(%q) returned an unexpected error: %v", tc.path, err)
			}

			var got *inventory.SensitiveData
			if len(gotInv.SensitiveData) > 0 {
				got = gotInv.SensitiveData[0]
			}

			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Extract(%q) returned diff (-want +got):\n%s", tc.path, diff)
			}
		})
	}
}
