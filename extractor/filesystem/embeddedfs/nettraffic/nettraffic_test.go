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

package nettraffic_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/nettraffic"
)

type mockFileAPI struct {
	path string
}

func (m *mockFileAPI) Path() string { return m.path }
func (m *mockFileAPI) Stat() (fs.FileInfo, error) { return nil, nil }

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"pcap file", "test.pcap", true},
		{"pcapng file", "test.pcapng", true},
		{"uppercase pcap", "test.PCAP", true},
		{"uppercase pcapng", "test.PCAPNG", true},
		{"other file", "test.txt", false},
	}
	
	e, _ := nettraffic.New(nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &mockFileAPI{path: tt.path}
			if got := e.FileRequired(api); got != tt.want {
				t.Errorf("Extractor.FileRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}
