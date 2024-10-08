// Copyright 2024 Google LLC
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

package spdx_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

var doc = &v2_3.Document{
	SPDXVersion:    "SPDX-2.3",
	DataLicense:    "CC0-1.0",
	SPDXIdentifier: "Document",
	DocumentName:   "Document name",
	CreationInfo: &v2_3.CreationInfo{
		Created: "2006-01-02T15:04:05Z",
	},
}

func TestWrite23(t *testing.T) {
	testDirPath := t.TempDir()
	testCases := []struct {
		desc   string
		format string
		want   string
	}{
		{
			desc:   "tag-value",
			format: "spdx23-tag-value",
			want:   "testdata/tag-value-format.spdx",
		},
		{
			desc:   "yaml",
			format: "spdx23-yaml",
			want:   "testdata/yaml-format",
		},
		{
			desc:   "json",
			format: "spdx23-json",
			want:   "testdata/json-format.spdx.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fullPath := filepath.Join(testDirPath, "output")
			err := spdx.Write23(doc, fullPath, tc.format)
			if err != nil {
				t.Fatalf("spdx.Write23(%v, %s, %s) returned an error: %v", doc, fullPath, tc.format, err)
			}

			got, err := os.ReadFile(fullPath)
			if err != nil {
				t.Fatalf("error while reading %s: %v", fullPath, err)
			}
			want, err := os.ReadFile(tc.want)
			if err != nil {
				t.Fatalf("error while reading %s: %v", tc.want, err)
			}
			wantStr := strings.TrimSpace(string(want))
			gotStr := strings.TrimSpace(string(got))
			if runtime.GOOS == "windows" {
				wantStr = strings.ReplaceAll(wantStr, "\r", "")
				gotStr = strings.ReplaceAll(gotStr, "\r", "")
			}

			if diff := cmp.Diff(wantStr, gotStr); diff != "" {
				t.Errorf("spdx.Write23(%v, %s, %s) produced unexpected results, diff (-want +got):\n%s", doc, fullPath, tc.format, diff)
			}
		})
	}
}

func TestWrite_InvalidFormat(t *testing.T) {
	testDirPath := t.TempDir()
	fullPath := filepath.Join(testDirPath, "output")
	format := "invalid-format"
	if err := spdx.Write23(doc, fullPath, format); err == nil ||
		!strings.Contains(err.Error(), "invalid SPDX format") {
		t.Errorf("spdx.Write23(%s, %s) didn't return an invalid extension error: %v", fullPath, format, err)
	}
}
