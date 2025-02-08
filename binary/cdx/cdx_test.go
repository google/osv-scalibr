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

package cdx_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/cdx"
)

var doc *cyclonedx.BOM

//nolint:gochecknoinits
func init() {
	doc = cyclonedx.NewBOM()
	doc.Metadata = &cyclonedx.Metadata{
		Timestamp: "2006-01-02T15:04:05Z",
		Component: &cyclonedx.Component{
			Name: "BOM name",
		},
	}
}

func TestWrite(t *testing.T) {
	testDirPath := t.TempDir()
	testCases := []struct {
		desc   string
		format string
		want   string
	}{
		{
			desc:   "xml",
			format: "cdx-xml",
			want:   "testdata/doc.cyclonedx.xml",
		},
		{
			desc:   "json",
			format: "cdx-json",
			want:   "testdata/doc.cyclonedx.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fullPath := filepath.Join(testDirPath, "output")
			err := cdx.Write(doc, fullPath, tc.format)
			if err != nil {
				t.Fatalf("cdx.Write(%v, %s, %s) returned an error: %v", doc, fullPath, tc.format, err)
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
				t.Errorf("cdx.Write(%v, %s, %s) produced unexpected results, diff (-want +got):\n%s", doc, fullPath, tc.format, diff)
			}
		})
	}
}

func TestWrite_InvalidFormat(t *testing.T) {
	testDirPath := t.TempDir()
	fullPath := filepath.Join(testDirPath, "output")
	format := "invalid-format"
	if err := cdx.Write(doc, fullPath, format); err == nil ||
		!strings.Contains(err.Error(), "invalid CDX format") {
		t.Errorf("cdx.Write(%s, %s) didn't return an invalid extension error: %v", fullPath, format, err)
	}
}
