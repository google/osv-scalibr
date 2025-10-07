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

package scanrunner_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"archive/tar"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scalibr/binary/cli"
	"github.com/google/osv-scalibr/binary/scanrunner"
	"google.golang.org/protobuf/encoding/prototext"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func createDetectorTestFiles(t *testing.T) string {
	// Create an /etc/passwd file for the example detector.
	t.Helper()
	dir := t.TempDir()
	passwdDir := filepath.Join(dir, "etc")
	if err := os.Mkdir(passwdDir, 0777); err != nil {
		t.Fatalf("error creating directory %v: %v", passwdDir, err)
	}
	passwdFile := filepath.Join(passwdDir, "passwd")
	if err := os.WriteFile(passwdFile, []byte("content"), 0644); err != nil {
		t.Fatalf("Error while creating file %s: %v", passwdFile, err)
	}
	return dir
}

func createExtractorTestFiles(t *testing.T) string {
	// Move an example python metadata file into the test dir for the wheelegg extractor.
	t.Helper()
	dir := t.TempDir()
	distDir := filepath.Join(dir, "pip.dist-info")
	if err := os.Mkdir(distDir, 0777); err != nil {
		t.Fatalf("error creating directory %v: %v", distDir, err)
	}
	srcFile := "../../extractor/filesystem/language/python/wheelegg/testdata/distinfo_meta"
	dstFile := filepath.Join(distDir, "METADATA")
	data, err := os.ReadFile(srcFile)
	if err != nil {
		t.Errorf("os.ReadFile(%v): %v", srcFile, err)
	}
	if err := os.WriteFile(dstFile, data, 0644); err != nil {
		t.Fatalf("os.WriteFile(%s): %v", dstFile, err)
	}
	return dir
}

func createFailingDetectorTestFiles(t *testing.T) string {
	// /etc/passwd can't be read.
	t.Helper()
	dir := t.TempDir()
	passwdDir := filepath.Join(dir, "etc")
	if err := os.Mkdir(passwdDir, 0600); err != nil {
		t.Fatalf("error creating directory %v: %v", passwdDir, err)
	}
	return dir
}

func createImageTarball(t *testing.T) string {
	t.Helper()

	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	gomod := `
module my-library

require (
	github.com/BurntSushi/toml v1.0.0
	gopkg.in/yaml.v2 v2.4.0
)
	`
	files := []struct {
		name, contents string
	}{
		{"go.mod", gomod},
	}
	for _, file := range files {
		hdr := &tar.Header{
			Name:     file.name,
			Mode:     0600,
			Size:     int64(len(file.contents)),
			Typeflag: tar.TypeReg,
		}
		if err := w.WriteHeader(hdr); err != nil {
			t.Fatalf("couldn't write header for %s: %v", file.name, err)
		}
		if _, err := w.Write([]byte(file.contents)); err != nil {
			t.Fatalf("couldn't write %s: %v", file.name, err)
		}
	}
	w.Close()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBuffer(buf.Bytes())), nil
	})
	if err != nil {
		t.Fatalf("unable to create layer: %v", err)
	}
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("unable to create image: %v", err)
	}

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "image.tar")
	if err := tarball.WriteToFile(tarPath, nil, image); err != nil {
		t.Fatalf("unable to write tarball: %v", err)
	}

	return dir
}

func createBadImageTarball(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(tarPath, []byte("bad tarball"), 0600); err != nil {
		t.Fatalf("unable to write tarball: %v", err)
	}
	return dir
}

func TestRunScan(t *testing.T) {
	testCases := []struct {
		desc              string
		setupFunc         func(t *testing.T) string
		flags             *cli.Flags
		wantExit          int
		wantScanStatus    spb.ScanStatus_ScanStatusEnum
		wantPluginStatus  []spb.ScanStatus_ScanStatusEnum
		wantPackagesCount int
		wantFindingCount  int
		excludeOS         []string // test will not run on these operating systems
	}{
		{
			desc:              "Successful detector run",
			setupFunc:         createDetectorTestFiles,
			flags:             &cli.Flags{DetectorsToRun: []string{"cis"}},
			wantScanStatus:    spb.ScanStatus_SUCCEEDED,
			wantPluginStatus:  []spb.ScanStatus_ScanStatusEnum{spb.ScanStatus_SUCCEEDED},
			wantPackagesCount: 0,
			wantFindingCount:  1,
			// TODO: b/343368902: Fix once we have a detector for Windows.
			excludeOS: []string{"windows"},
		},
		{
			desc:              "Successful extractor run",
			setupFunc:         createExtractorTestFiles,
			flags:             &cli.Flags{ExtractorsToRun: []string{"python/wheelegg"}},
			wantScanStatus:    spb.ScanStatus_SUCCEEDED,
			wantPluginStatus:  []spb.ScanStatus_ScanStatusEnum{spb.ScanStatus_SUCCEEDED},
			wantPackagesCount: 1,
			wantFindingCount:  0,
		},
		{
			desc:      "Successful image extractor run",
			setupFunc: createImageTarball,
			flags: &cli.Flags{
				ImageTarball:    "image.tar",
				ExtractorsToRun: []string{"go/gomod"},
			},
			wantScanStatus:    spb.ScanStatus_SUCCEEDED,
			wantPluginStatus:  []spb.ScanStatus_ScanStatusEnum{spb.ScanStatus_SUCCEEDED},
			wantPackagesCount: 2,
			wantFindingCount:  0,
		},
		{
			desc:      "Failure to read image tarball",
			setupFunc: createBadImageTarball,
			flags: &cli.Flags{
				ImageTarball:    "image.tar",
				ExtractorsToRun: []string{"go/gomod"},
			},
			wantExit:          1,
			wantScanStatus:    spb.ScanStatus_FAILED,
			wantPluginStatus:  []spb.ScanStatus_ScanStatusEnum{spb.ScanStatus_FAILED},
			wantPackagesCount: 0,
			wantFindingCount:  0,
		},
		{
			desc:              "Unsuccessful plugin run",
			setupFunc:         createFailingDetectorTestFiles,
			flags:             &cli.Flags{DetectorsToRun: []string{"cis"}},
			wantExit:          1,
			wantScanStatus:    spb.ScanStatus_PARTIALLY_SUCCEEDED,
			wantPluginStatus:  []spb.ScanStatus_ScanStatusEnum{spb.ScanStatus_FAILED},
			wantPackagesCount: 0,
			wantFindingCount:  0,
			// TODO: b/343368902: Fix once we have a detector for Windows.
			excludeOS: []string{"windows"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if slices.Contains(tc.excludeOS, runtime.GOOS) {
				t.Skipf("Skipping test on %s", runtime.GOOS)
			}

			dir := tc.setupFunc(t)
			resultFile := filepath.Join(dir, "result.textproto")
			tc.flags.ResultFile = resultFile

			if tc.flags.ImageTarball != "" {
				tc.flags.ImageTarball = filepath.Join(dir, tc.flags.ImageTarball)
			} else {
				tc.flags.Root = dir
			}

			gotExit := scanrunner.RunScan(tc.flags)
			if gotExit != tc.wantExit {
				t.Fatalf("result.RunScan(%v) = %d, want %d", tc.flags, gotExit, tc.wantExit)
			}
			_, err := os.Stat(resultFile)
			if gotExit == 0 && errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Scan returned successful exit code 0 but no result file was created")
			}
			if gotExit != 0 && errors.Is(err, os.ErrNotExist) {
				// It is expected that no results are created if the scan fails. Nothing else to check.
				return
			}

			output, err := os.ReadFile(resultFile)
			if err != nil {
				t.Fatalf("os.ReadFile(%v): %v", resultFile, err)
			}

			result := &spb.ScanResult{}
			if err = prototext.Unmarshal(output, result); err != nil {
				t.Fatalf("prototext.Unmarshal(%v): %v", result, err)
			}
			if result.Status.Status != tc.wantScanStatus {
				t.Errorf("Unexpected scan status, want %v got %v", tc.wantScanStatus, result.Status.Status)
			}
			gotPS := []spb.ScanStatus_ScanStatusEnum{}
			for _, s := range result.PluginStatus {
				gotPS = append(gotPS, s.Status.Status)
			}
			if diff := cmp.Diff(tc.wantPluginStatus, gotPS); diff != "" {
				t.Errorf("Unexpected plugin status (-want +got):\n%s", diff)
			}
			if len(result.Inventory.Packages) != tc.wantPackagesCount {
				t.Errorf("Unexpected package count, want %d got %d", tc.wantPackagesCount, len(result.Inventory.Packages))
			}
			if len(result.Inventory.GenericFindings) != tc.wantFindingCount {
				t.Errorf("Unexpected finding count, want %d got %d", tc.wantFindingCount, len(result.Inventory.GenericFindings))
			}
		})
	}
}
