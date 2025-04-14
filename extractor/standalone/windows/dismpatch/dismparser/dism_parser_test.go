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

package dismparser

import (
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParse(t *testing.T) {
	content, err := os.ReadFile("testdata/dism_testdata.txt")
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	packages, imgVersion, err := Parse(string(content))
	if err != nil {
		t.Errorf("Error while parsing the output: %v", err)
	}

	if imgVersion != "10.0.17763.3406" {
		t.Errorf("Parse, ImageVersion: Got: %v, Want: %v", imgVersion, "10.0.17763.3406")
	}

	want := []DismPkg{
		{
			PackageIdentity: "Microsoft-Windows-FodMetadata-Package~31bf3856ad364e35~amd64~~10.0.17763.1",
			PackageVersion:  "10.0.17763.1",
			State:           "Installed",
			ReleaseType:     "Feature Pack",
			InstallTime:     "9/15/2018 9:08 AM",
		},
		{
			PackageIdentity: "Package_for_KB4470788~31bf3856ad364e35~amd64~~17763.164.1.1",
			PackageVersion:  "17763.164.1.1",
			State:           "Installed",
			ReleaseType:     "Security Update",
			InstallTime:     "3/12/2019 6:27 AM",
		},
		{
			PackageIdentity: "Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.3406.1.5",
			PackageVersion:  "17763.3406.1.5",
			State:           "Installed",
			ReleaseType:     "Security Update",
			InstallTime:     "9/13/2022 11:06 PM",
		},
		{
			PackageIdentity: "Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.379.1.11",
			PackageVersion:  "17763.379.1.11",
			State:           "Superseded",
			ReleaseType:     "Security Update",
			InstallTime:     "3/12/2019 6:31 AM",
		},
		{
			PackageIdentity: "Package_for_ServicingStack_3232~31bf3856ad364e35~amd64~~17763.3232.1.1",
			PackageVersion:  "17763.3232.1.1",
			State:           "Installed",
			ReleaseType:     "Update",
			InstallTime:     "9/13/2022 10:46 PM",
		},
		{
			PackageIdentity: "Microsoft-Windows-WordPad-FoD-Package~31bf3856ad364e35~wow64~en-US~10.0.19041.1",
			PackageVersion:  "10.0.19041.1",
			State:           "Installed",
			ReleaseType:     "OnDemand Pack",
			InstallTime:     "12/7/2019 9:51 AM",
		},
	}

	if diff := cmp.Diff(want, packages); diff != "" {
		t.Errorf("Parse: Diff = %v", diff)
	}
}

func TestFindVersion(t *testing.T) {
	type test struct {
		input string
		want  string
	}

	tests := []test{
		{
			input: "Microsoft-Windows-FodMetadata-Package~31bf3856ad364e35~amd64~~10.0.17763.1",
			want:  "10.0.17763.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := findVersion(tt.input)
			if got != tt.want {
				t.Errorf("findVersion: Got: %v, Want: %v", got, tt.want)
			}
		})
	}
}

func TestParseError(t *testing.T) {
	content, err := os.ReadFile("testdata/err_testdata.txt")
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	_, _, err = Parse(string(content))
	if !errors.Is(err, ErrParsingError) {
		t.Errorf("Parse: Want: %v, Got: %v", ErrParsingError, err)
	}
}
