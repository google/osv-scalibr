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

package spdx_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/spdx"
	convspdx "github.com/google/osv-scalibr/converter/spdx"
)

const ns = "https://spdx.google/test"

var doc3 = &convspdx.Document3{
	Context: convspdx.SPDX3Context,
	Graph: []any{
		&convspdx.CreationInfo3{
			ID:          "_:creationInfo_0",
			Type:        convspdx.TypeCreationInfo,
			SpecVersion: convspdx.SPDX3Version,
			Created:     "2006-01-02T15:04:05Z",
			CreatedBy:   []string{ns + "/SPDXRef-Agent-SCALIBR"},
		},
		&convspdx.SpdxDocument3{
			Element3: convspdx.Element3{
				SPDXID:       ns + "/SPDXRef-DOCUMENT",
				Type:         convspdx.TypeSpdxDocument,
				Name:         "Document name",
				CreationInfo: "_:creationInfo_0",
			},
			RootElement:        []string{ns + "/SPDXRef-Package-main"},
			ProfileConformance: []string{"core", "software"},
		},
		&convspdx.Package3{
			Element3: convspdx.Element3{
				SPDXID:       ns + "/SPDXRef-Package-main",
				Type:         convspdx.TypePackage,
				Name:         "main",
				CreationInfo: "_:creationInfo_0",
			},
			PackageVersion: "0",
		},
	},
}

func TestWrite3(t *testing.T) {
	testDirPath := t.TempDir()
	format := "spdx3-json"
	want := "testdata/json-format.spdx3.json"

	fullPath := filepath.Join(testDirPath, "output")
	if err := spdx.Write3(doc3, fullPath, format); err != nil {
		t.Fatalf("spdx.Write3(%v, %s, %s) returned an error: %v", doc3, fullPath, format, err)
	}

	got, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("error while reading %s: %v", fullPath, err)
	}
	wantBytes, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("error while reading %s: %v", want, err)
	}
	wantStr := strings.TrimSpace(string(wantBytes))
	gotStr := strings.TrimSpace(string(got))
	if runtime.GOOS == "windows" {
		wantStr = strings.ReplaceAll(wantStr, "\r", "")
		gotStr = strings.ReplaceAll(gotStr, "\r", "")
	}

	if diff := cmp.Diff(wantStr, gotStr); diff != "" {
		t.Errorf("spdx.Write3(%v, %s, %s) produced unexpected results, diff (-want +got):\n%s", doc3, fullPath, format, diff)
	}
}

func TestWrite3_InvalidFormat(t *testing.T) {
	testDirPath := t.TempDir()
	fullPath := filepath.Join(testDirPath, "output")
	format := "spdx3-yaml"
	if err := spdx.Write3(doc3, fullPath, format); err == nil ||
		!strings.Contains(err.Error(), "invalid SPDX format") {
		t.Errorf("spdx.Write3(%s, %s) didn't return an invalid extension error: %v", fullPath, format, err)
	}
}
