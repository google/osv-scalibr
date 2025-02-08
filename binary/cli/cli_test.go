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

package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/binary/cli"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/plugin"
)

func TestValidateFlags(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		flags   *cli.Flags
		wantErr error
	}{
		{
			desc: "Valid config",
			flags: &cli.Flags{
				Root:            "/",
				ResultFile:      "result.textproto",
				Output:          []string{"textproto=result2.textproto", "spdx23-yaml=result.spdx.yaml"},
				ExtractorsToRun: []string{"java,python", "javascript"},
				DetectorsToRun:  []string{"cve,cis"},
				DirsToSkip:      []string{"path1,path2", "path3"},
				SPDXCreators:    "Tool:SCALIBR,Organization:Google",
			},
			wantErr: nil,
		},
		{
			desc:    "Either output flag missing",
			flags:   &cli.Flags{Root: "/"},
			wantErr: cmpopts.AnyError,
		}, {
			desc: "Result flag present",
			flags: &cli.Flags{
				Root:       "/",
				ResultFile: "result.textproto",
			},
			wantErr: nil,
		}, {
			desc: "Output flag present",
			flags: &cli.Flags{
				Root:   "/",
				Output: []string{"textproto=result.textproto"},
			},
			wantErr: nil,
		}, {
			desc: "Wrong result extension",
			flags: &cli.Flags{
				Root:       "/",
				ResultFile: "result.png",
			},
			wantErr: cmpopts.AnyError,
		}, {
			desc: "Invalid output format",
			flags: &cli.Flags{
				Root:   "/",
				Output: []string{"invalid"},
			},
			wantErr: cmpopts.AnyError,
		}, {
			desc: "Unknown output format",
			flags: &cli.Flags{
				Root:   "/",
				Output: []string{"unknown=foo.bar"},
			},
			wantErr: cmpopts.AnyError,
		}, {
			desc: "Wrong output extension",
			flags: &cli.Flags{
				Root:   "/",
				Output: []string{"proto=result.png"},
			},
			wantErr: cmpopts.AnyError,
		}, {
			desc: "Invalid extractors",
			flags: &cli.Flags{
				Root:            "/",
				ResultFile:      "result.textproto",
				ExtractorsToRun: []string{",python"},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Nonexistent extractors",
			flags: &cli.Flags{
				Root:            "/",
				ResultFile:      "result.textproto",
				ExtractorsToRun: []string{"asdf"},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Invalid detectors",
			flags: &cli.Flags{
				Root:           "/",
				ResultFile:     "result.textproto",
				DetectorsToRun: []string{"cve,"},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Nonexistent detectors",
			flags: &cli.Flags{
				Root:           "/",
				ResultFile:     "result.textproto",
				DetectorsToRun: []string{"asdf"},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Detector with missing extractor dependency when ExplicitExtractors",
			flags: &cli.Flags{
				Root:               "/",
				ResultFile:         "result.textproto",
				ExtractorsToRun:    []string{"python,javascript"},
				DetectorsToRun:     []string{"govulncheck"}, // Needs the Go binary extractor.
				ExplicitExtractors: true,
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Detector with missing extractor dependency (enabled automatically)",
			flags: &cli.Flags{
				Root:            "/",
				ResultFile:      "result.textproto",
				ExtractorsToRun: []string{"python,javascript"},
				DetectorsToRun:  []string{"govulncheck"}, // Needs the Go binary extractor.
			},
			wantErr: nil,
		},
		{
			desc: "Invalid paths to skip",
			flags: &cli.Flags{
				Root:       "/",
				ResultFile: "result.textproto",
				DirsToSkip: []string{"path1,,path3"},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Invalid glob for skipping directories",
			flags: &cli.Flags{
				Root:        "/",
				ResultFile:  "result.textproto",
				SkipDirGlob: "[",
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Invalid SPDX creator format",
			flags: &cli.Flags{
				Root:         "/",
				SPDXCreators: "invalid:creator:format",
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Image Platform without Remote Image",
			flags: &cli.Flags{
				ImagePlatform: "linux/amd64",
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Image Platform with Remote Image",
			flags: &cli.Flags{
				RemoteImage:   "docker",
				ImagePlatform: "linux/amd64",
				ResultFile:    "result.textproto",
			},
			wantErr: nil,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := cli.ValidateFlags(tc.flags)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("cli.ValidateFlags(%v) error got diff (-want +got):\n%s", tc.flags, diff)
			}
		})
	}
}

func TestGetScanConfig_ScanRoots(t *testing.T) {
	for _, tc := range []struct {
		desc          string
		flags         map[string]*cli.Flags
		wantScanRoots map[string][]string
	}{
		{
			desc: "Default scan roots",
			flags: map[string]*cli.Flags{
				"darwin":  {},
				"linux":   {},
				"windows": {},
			},
			wantScanRoots: map[string][]string{
				"darwin":  {"/"},
				"linux":   {"/"},
				"windows": {"C:\\"},
			},
		},
		{
			desc: "Scan root are provided and used",
			flags: map[string]*cli.Flags{
				"darwin":  {Root: "/root"},
				"linux":   {Root: "/root"},
				"windows": {Root: "C:\\myroot"},
			},
			wantScanRoots: map[string][]string{
				"darwin":  {"/root"},
				"linux":   {"/root"},
				"windows": {"C:\\myroot"},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			wantScanRoots, ok := tc.wantScanRoots[runtime.GOOS]
			if !ok {
				t.Fatalf("Current system %q not supported, please add test cases", runtime.GOOS)
			}

			flags, ok := tc.flags[runtime.GOOS]
			if !ok {
				t.Fatalf("Current system %q not supported, please add test cases", runtime.GOOS)
			}

			cfg, err := flags.GetScanConfig()
			if err != nil {
				t.Errorf("%v.GetScanConfig(): %v", flags, err)
			}
			gotScanRoots := []string{}
			for _, r := range cfg.ScanRoots {
				gotScanRoots = append(gotScanRoots, r.Path)
			}
			if diff := cmp.Diff(wantScanRoots, gotScanRoots); diff != "" {
				t.Errorf("%v.GetScanConfig() ScanRoots got diff (-want +got):\n%s", flags, diff)
			}
		})
	}
}

func TestGetScanConfig_DirsToSkip(t *testing.T) {
	for _, tc := range []struct {
		desc           string
		flags          map[string]*cli.Flags
		wantDirsToSkip map[string][]string
	}{
		{
			desc: "Skip default dirs",
			flags: map[string]*cli.Flags{
				"darwin":  {Root: "/"},
				"linux":   {Root: "/"},
				"windows": {Root: "C:\\"},
			},
			wantDirsToSkip: map[string][]string{
				"darwin":  {"/dev", "/proc", "/sys"},
				"linux":   {"/dev", "/proc", "/sys"},
				"windows": {"C:\\Windows"},
			},
		},
		{
			desc: "Skip additional dirs",
			flags: map[string]*cli.Flags{
				"darwin": {
					Root:       "/",
					DirsToSkip: []string{"/boot,/mnt,C:\\boot", "C:\\mnt"},
				},
				"linux": {
					Root:       "/",
					DirsToSkip: []string{"/boot,/mnt", "C:\\boot,C:\\mnt"},
				},
				"windows": {
					Root:       "C:\\",
					DirsToSkip: []string{"C:\\boot,C:\\mnt"},
				},
			},
			wantDirsToSkip: map[string][]string{
				"darwin":  {"/dev", "/proc", "/sys", "/boot", "/mnt"},
				"linux":   {"/dev", "/proc", "/sys", "/boot", "/mnt"},
				"windows": {"C:\\Windows", "C:\\boot", "C:\\mnt"},
			},
		},
		{
			desc: "Ignore paths outside root",
			flags: map[string]*cli.Flags{
				"darwin": {
					Root:       "/root",
					DirsToSkip: []string{"/root/dir1,/dir2"},
				},
				"linux": {
					Root:       "/root",
					DirsToSkip: []string{"/root/dir1,/dir2"},
				},
				"windows": {
					Root:       "C:\\root",
					DirsToSkip: []string{"C:\\root\\dir1,c:\\dir2"},
				},
			},
			wantDirsToSkip: map[string][]string{
				"darwin":  {"/root/dir1"},
				"linux":   {"/root/dir1"},
				"windows": {"C:\\root\\dir1"},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			wantDirsToSkip, ok := tc.wantDirsToSkip[runtime.GOOS]
			if !ok {
				t.Fatalf("Current system %q not supported, please add test cases", runtime.GOOS)
			}

			flags, ok := tc.flags[runtime.GOOS]
			if !ok {
				t.Fatalf("Current system %q not supported, please add test cases", runtime.GOOS)
			}

			cfg, err := flags.GetScanConfig()
			if err != nil {
				t.Errorf("%v.GetScanConfig(): %v", flags, err)
			}
			if diff := cmp.Diff(wantDirsToSkip, cfg.DirsToSkip); diff != "" {
				t.Errorf("%v.GetScanConfig() dirsToSkip got diff (-want +got):\n%s", flags, diff)
			}
		})
	}
}

func TestGetScanConfig_SkipDirRegex(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		flags            *cli.Flags
		wantSkipDirRegex string
		wantNil          bool
	}{
		{
			desc: "simple regex",
			flags: &cli.Flags{
				Root:         "/",
				SkipDirRegex: "asdf.*foo",
			},
			wantSkipDirRegex: "asdf.*foo",
		},
		{
			desc: "no regex",
			flags: &cli.Flags{
				Root: "/",
			},
			wantNil: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cfg, err := tc.flags.GetScanConfig()
			if err != nil {
				t.Errorf("%v.GetScanConfig(): %v", tc.flags, err)
			}
			if tc.wantNil && cfg.SkipDirRegex != nil {
				t.Errorf("%v.GetScanConfig() SkipDirRegex got %q, want nil", tc.flags, cfg.SkipDirRegex)
			}
			if !tc.wantNil && tc.wantSkipDirRegex != cfg.SkipDirRegex.String() {
				t.Errorf("%v.GetScanConfig() SkipDirRegex got %q, want %q", tc.flags, cfg.SkipDirRegex.String(), tc.wantSkipDirRegex)
			}
		})
	}
}

func TestGetScanConfig_CreatePlugins(t *testing.T) {
	for _, tc := range []struct {
		desc               string
		flags              *cli.Flags
		wantExtractorCount int
		wantDetectorCount  int
	}{
		{
			desc: "Create an extractor",
			flags: &cli.Flags{
				ExtractorsToRun: []string{"python/wheelegg"},
			},
			wantExtractorCount: 1,
		},
		{
			desc: "Create a detector",
			flags: &cli.Flags{
				DetectorsToRun: []string{"cis"},
			},
			wantDetectorCount: 1,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cfg, err := tc.flags.GetScanConfig()
			if err != nil {
				t.Errorf("%v.GetScanConfig(): %v", tc.flags, err)
			}
			if len(cfg.Detectors) != tc.wantDetectorCount {
				t.Errorf("%v.GetScanConfig() want detector count %d got %d", tc.flags, tc.wantDetectorCount, len(cfg.Detectors))
			}
			if len(cfg.FilesystemExtractors) != tc.wantExtractorCount {
				t.Errorf("%v.GetScanConfig() want detector count %d got %d", tc.flags, tc.wantDetectorCount, len(cfg.Detectors))
			}
		})
	}
}

func TestGetScanConfig_GovulncheckParams(t *testing.T) {
	dbPath := "path/to/db"
	flags := &cli.Flags{
		ExtractorsToRun:   []string{"go"},
		DetectorsToRun:    []string{binary.Detector{}.Name()},
		GovulncheckDBPath: dbPath,
	}

	cfg, err := flags.GetScanConfig()
	if err != nil {
		t.Errorf("%v.GetScanConfig(): %v", flags, err)
	}
	if len(cfg.Detectors) != 1 {
		t.Fatalf("%v.GetScanConfig() want 1 detector got %d", flags, len(cfg.Detectors))
	}
	got := cfg.Detectors[0].(*binary.Detector).OfflineVulnDBPath
	if got != dbPath {
		t.Errorf("%v.GetScanConfig() want govulncheck detector with DB path %q got %q", flags, dbPath, got)
	}
}

func TestWriteScanResults(t *testing.T) {
	testDirPath := t.TempDir()
	result := &scalibr.ScanResult{
		Version: "1.2.3",
		Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
	}
	for _, tc := range []struct {
		desc              string
		flags             *cli.Flags
		wantFilename      string
		wantContentPrefix string
	}{
		{
			desc: "Create proto using --result flag",
			flags: &cli.Flags{
				ResultFile: filepath.Join(testDirPath, "result.textproto"),
			},
			wantFilename:      "result.textproto",
			wantContentPrefix: "version:",
		},
		{
			desc: "Create proto using --output flag",
			flags: &cli.Flags{
				Output: []string{"textproto=" + filepath.Join(testDirPath, "result2.textproto")},
			},
			wantFilename:      "result2.textproto",
			wantContentPrefix: "version:",
		},
		{
			desc: "Create SPDX 2.3",
			flags: &cli.Flags{
				Output: []string{"spdx23-tag-value=" + filepath.Join(testDirPath, "result.spdx")},
			},
			wantFilename:      "result.spdx",
			wantContentPrefix: "SPDXVersion: SPDX-2.3",
		},
		{
			desc: "Create CDX",
			flags: &cli.Flags{
				Output: []string{"cdx-json=" + filepath.Join(testDirPath, "result.cyclonedx.json")},
			},
			wantFilename:      "result.cyclonedx.json",
			wantContentPrefix: "{\n  \"$schema\": \"http://cyclonedx.org/schema/bom-1.6.schema.json\"",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if err := tc.flags.WriteScanResults(result); err != nil {
				t.Fatalf("%v.WriteScanResults(%v): %v", tc.flags, result, err)
			}

			fullPath := filepath.Join(testDirPath, tc.wantFilename)
			got, err := os.ReadFile(fullPath)
			if err != nil {
				t.Fatalf("error while reading %s: %v", fullPath, err)
			}
			gotStr := string(got)

			if !strings.HasPrefix(gotStr, tc.wantContentPrefix) {
				t.Errorf("%v.WriteScanResults(%v) want file with content prefix %q, got %q", tc.flags, result, tc.wantContentPrefix, gotStr)
			}
		})
	}
}
