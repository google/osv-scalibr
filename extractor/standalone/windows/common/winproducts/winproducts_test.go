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

package winproducts

import (
	"testing"
)

func TestWhichWindowsFlavor(t *testing.T) {
	tests := []struct {
		desc        string
		installType string
		want        string
	}{
		{
			desc:        "Windows server returns server",
			installType: "server",
			want:        "server",
		},
		{
			desc:        "Windows server core returns server",
			installType: "server core",
			want:        "server",
		},
		{
			desc:        "Windows client returns client",
			installType: "client",
			want:        "client",
		},
		{
			desc:        "Ignore case",
			installType: "SeRvEr",
			want:        "server",
		},
		{
			desc:        "Unknown returns server",
			installType: "unknown",
			want:        "server",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := windowsFlavor(tc.installType)
			if got != tc.want {
				t.Errorf("WhichWindowsFlavor(%q) = %q, want: %q", tc.installType, got, tc.want)
			}
		})
	}
}

func TestWindowsProductFromVersion(t *testing.T) {
	tests := []struct {
		desc       string
		flavor     string
		imgVersion string
		want       string
	}{
		{
			desc:       "Known version returns correct product",
			flavor:     "server",
			imgVersion: "10.0.14393.1234",
			want:       "windows_server_2016",
		},
		{
			desc:       "Unknown version returns unknownWindows",
			flavor:     "server",
			imgVersion: "127.0.0.1",
			want:       "unknownWindows",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := WindowsProductFromVersion(tc.flavor, tc.imgVersion)
			if got != tc.want {
				t.Errorf("WindowsProductFromVersion(%q, %q) = %q, want: %q", tc.flavor, tc.imgVersion, got, tc.want)
			}
		})
	}
}
