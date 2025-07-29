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

package proto_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/proto"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestWrite(t *testing.T) {
	testDirPath := t.TempDir()
	var result = &spb.ScanResult{Version: "1.0.0"}
	testCases := []struct {
		desc           string
		path           string
		expectedPrefix string
	}{
		{
			desc:           "textproto",
			path:           "output.textproto",
			expectedPrefix: "version:",
		},
		{
			desc:           "binproto",
			path:           "output.binproto",
			expectedPrefix: "\x0a\x051.0.0",
		},
		{
			desc:           "gzipped file",
			path:           "output.textproto.gz",
			expectedPrefix: "\x1f\x8b",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fullPath := filepath.Join(testDirPath, tc.path)
			err := proto.Write(fullPath, result)
			if err != nil {
				t.Fatalf("proto.Write(%s, %v) returned an error: %v", fullPath, result, err)
			}

			content, err := os.ReadFile(fullPath)
			if err != nil {
				t.Fatalf("error while reading %s: %v", fullPath, err)
			}
			prefix := content[:len(tc.expectedPrefix)]
			if diff := cmp.Diff(tc.expectedPrefix, string(prefix)); diff != "" {
				t.Errorf("%s contains unexpected prefix, diff (-want +got):\n%s", fullPath, diff)
			}
		})
	}
}

func TestWrite_InvalidFilename(t *testing.T) {
	testDirPath := t.TempDir()
	testPaths := []string{
		"config.invalid-extension",
		"config.invalid-extension.gz",
		"no-extension",
		"no-extension.gz",
	}
	for _, p := range testPaths {
		fullPath := filepath.Join(testDirPath, p)
		if err := proto.Write(fullPath, &spb.ScanResult{}); err == nil ||
			!strings.HasPrefix(err.Error(), "invalid filename") {
			t.Errorf("proto.Write(%s) didn't return an invalid file error: %v", fullPath, err)
		}
	}
}

func TestWriteWithFormat(t *testing.T) {
	testDirPath := t.TempDir()
	var result = &spb.ScanResult{Version: "1.0.0"}
	testCases := []struct {
		desc           string
		format         string
		expectedPrefix string
	}{
		{
			desc:           "textproto",
			format:         "textproto",
			expectedPrefix: "version:",
		},
		{
			desc:           "binproto",
			format:         "binproto",
			expectedPrefix: "\x0a\x051.0.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fullPath := filepath.Join(testDirPath, "output")
			err := proto.WriteWithFormat(fullPath, result, tc.format)
			if err != nil {
				t.Fatalf("proto.WriteWithFormat(%s, %v, %s) returned an error: %v", fullPath, result, tc.format, err)
			}

			content, err := os.ReadFile(fullPath)
			if err != nil {
				t.Fatalf("error while reading %s: %v", fullPath, err)
			}
			prefix := content[:len(tc.expectedPrefix)]
			if diff := cmp.Diff(tc.expectedPrefix, string(prefix)); diff != "" {
				t.Errorf("%s contains unexpected prefix, diff (-want +got):\n%s", fullPath, diff)
			}
		})
	}
}
