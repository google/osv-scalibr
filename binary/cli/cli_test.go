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

package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/binary/cli"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/plugin"
	scalibr "github.com/google/osv-scalibr"
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
				ExtractorsToRun: "java,python",
				DetectorsToRun:  "cve,cis",
				DirsToSkip:      "path1,path2",
				SPDXCreators:    "Tool:SCALIBR,Organization:Google",
			},
			wantErr: nil,
		},
		{
			desc:    "Root missing",
			flags:   &cli.Flags{ResultFile: "result.textproto"},
			wantErr: cmpopts.AnyError,
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
				ExtractorsToRun: ",python",
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Nonexistent extractors",
			flags: &cli.Flags{
				Root:            "/",
				ResultFile:      "result.textproto",
				ExtractorsToRun: "asdf",
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Invalid detectors",
			flags: &cli.Flags{
				Root:           "/",
				ResultFile:     "result.textproto",
				DetectorsToRun: "cve,",
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Nonexistent detectors",
			flags: &cli.Flags{
				Root:           "/",
				ResultFile:     "result.textproto",
				DetectorsToRun: "asdf",
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Detector with missing extractor dependency",
			flags: &cli.Flags{
				Root:            "/",
				ResultFile:      "result.textproto",
				ExtractorsToRun: "python,javascript",
				DetectorsToRun:  "govulncheck", // Needs the Go binary extractor.
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Invalid paths to skip",
			flags: &cli.Flags{
				Root:       "/",
				ResultFile: "result.textproto",
				DirsToSkip: "path1,,path3",
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
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := cli.ValidateFlags(tc.flags)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("cli.ValidateFlags(%v) error got diff (-want +got):\n%s", tc.flags, diff)
			}
		})
	}
}

func TestGetScanConfig_DirsToSkip(t *testing.T) {
	for _, tc := range []struct {
		desc           string
		flags          *cli.Flags
		wantDirsToSkip []string
	}{
		{
			desc: "Skip default dirs",
			flags: &cli.Flags{
				Root: "/",
			},
			wantDirsToSkip: []string{"/dev", "/proc", "/sys"},
		},
		{
			desc: "Skip additional dirs",
			flags: &cli.Flags{
				Root:       "/",
				DirsToSkip: "/boot,/mnt",
			},
			wantDirsToSkip: []string{"/dev", "/proc", "/sys", "/boot", "/mnt"},
		},
		{
			desc: "Ignore paths outside root",
			flags: &cli.Flags{
				Root:       "/root",
				DirsToSkip: "/root/dir1,/dir2",
			},
			wantDirsToSkip: []string{"/root/dir1"},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cfg, err := tc.flags.GetScanConfig()
			if err != nil {
				t.Errorf("%v.GetScanConfig(): %v", tc.flags, err)
			}
			if diff := cmp.Diff(tc.wantDirsToSkip, cfg.DirsToSkip); diff != "" {
				t.Errorf("%v.GetScanConfig() dirsToSkip got diff (-want +got):\n%s", tc.flags, diff)
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
				ExtractorsToRun: "python/wheelegg",
			},
			wantExtractorCount: 1,
		},
		{
			desc: "Create a detector",
			flags: &cli.Flags{
				DetectorsToRun: "cis",
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
		ExtractorsToRun:   "go",
		DetectorsToRun:    binary.Detector{}.Name(),
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
