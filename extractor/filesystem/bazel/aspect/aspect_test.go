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

package aspect_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/bazel/aspect"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
)

type mockCommandRunner struct {
	lookPathFunc func(file string) (string, error)
	runFunc      func(ctx context.Context, dir string, name string, args ...string) error
}

func (m *mockCommandRunner) LookPath(file string) (string, error) {
	if m.lookPathFunc != nil {
		return m.lookPathFunc(file)
	}
	return "/usr/bin/" + file, nil
}

func (m *mockCommandRunner) Run(ctx context.Context, dir string, name string, args ...string) error {
	if m.runFunc != nil {
		return m.runFunc(ctx, dir, name, args...)
	}
	return nil
}

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "empty",
			inputPath: "",
			want:      false,
		},
		{
			name:      "workspace",
			inputPath: "WORKSPACE",
			want:      true,
		},
		{
			name:      "workspace_bazel",
			inputPath: "WORKSPACE.bazel",
			want:      true,
		},
		{
			name:      "module_bazel",
			inputPath: "MODULE.bazel",
			want:      true,
		},
		{
			name:      "build",
			inputPath: "BUILD",
			want:      false,
		},
		{
			name:      "build_bazel",
			inputPath: "BUILD.bazel",
			want:      false,
		},
		{
			name:      "nested_workspace",
			inputPath: "path/to/my/WORKSPACE",
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := aspect.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("aspect.New() error: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	type aspectTestData struct {
		Name           string `json:"name,omitempty"`
		Label          string `json:"label,omitempty"`
		Kind           string `json:"kind,omitempty"`
		Version        string `json:"version,omitempty"`
		Tag            string `json:"tag,omitempty"`
		Commit         string `json:"commit,omitempty"`
		URL            string `json:"url,omitempty"`
		URLs           string `json:"urls,omitempty"`
		StripPrefix    string `json:"strip_prefix,omitempty"`
		Remote         string `json:"remote,omitempty"`
		PackageName    string `json:"package_name,omitempty"`
		PackageVersion string `json:"package_version,omitempty"`
		PackageURL     string `json:"package_url,omitempty"`
	}

	tests := []struct {
		name         string
		setupFs      func(t *testing.T, wsDir string)
		pluginConfig *cpb.PluginConfig
		mockRunner   func(t *testing.T, wsDir string) aspect.CommandRunner
		scanPath     string
		wantInv      inventory.Inventory
		wantErr      error
	}{
		{
			name: "success_with_mixed_dependency_types_and_deduplication",
			setupFs: func(t *testing.T, wsDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(wsDir, "WORKSPACE"), []byte(""), 0644); err != nil {
					t.Fatalf("failed to create WORKSPACE: %v", err)
				}
			},
			scanPath: "WORKSPACE",
			mockRunner: func(t *testing.T, wsDir string) aspect.CommandRunner {
				t.Helper()
				return &mockCommandRunner{
					lookPathFunc: func(file string) (string, error) {
						return "/usr/bin/bazel", nil
					},
					runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
						if name != "bazel" {
							t.Errorf("got command name %q, want %q", name, "bazel")
						}
						if dir != wsDir {
							t.Errorf("got working dir %q, want %q", dir, wsDir)
						}

						// Extract BEP path from args
						var bepPath string
						for _, arg := range args {
							if after, ok := strings.CutPrefix(arg, "--build_event_json_file="); ok {
								bepPath = after
							}
						}
						if bepPath == "" {
							t.Fatal("missing --build_event_json_file argument")
						}

						// Create mock aspect output JSON files
						aspectOutputs := []aspectTestData{
							{
								Name:           "custom_lib",
								Label:          "//libs:custom",
								Kind:           "cc_library",
								PackageName:    "my-awesome-lib",
								PackageVersion: "2.1.0",
								PackageURL:     "pkg:generic/my-awesome-lib@2.1.0",
							},
							{
								// Duplicate of custom_lib by PackageName -> should be deduplicated
								Name:           "custom_lib_alias",
								Label:          "//libs:custom_alias",
								Kind:           "cc_library",
								PackageName:    "my-awesome-lib",
								PackageVersion: "2.1.0",
							},
							{
								Name:    "pip__requests",
								Label:   "@@pip__requests//:pkg",
								Kind:    "py_library",
								Version: "2.31.0",
							},
						}

						outDir := filepath.Dir(bepPath)
						var bepLines []string

						for i, item := range aspectOutputs {
							data, err := json.Marshal(item)
							if err != nil {
								t.Fatalf("failed to marshal aspect output: %v", err)
							}
							jsonPath := filepath.Join(outDir, fmt.Sprintf("target_%d.scalibr.json", i))
							if err := os.WriteFile(jsonPath, data, 0644); err != nil {
								t.Fatalf("failed to write aspect json: %v", err)
							}
							bepLines = append(bepLines, fmt.Sprintf(`{"id":{"namedSet":{"id":"%d"}},"namedSetOfFiles":{"files":[{"uri":"file://%s"}]}}`, i, jsonPath))
						}

						return os.WriteFile(bepPath, []byte(strings.Join(bepLines, "\n")), 0644)
					},
				}
			},
			wantInv: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "my-awesome-lib",
						Version:  "2.1.0",
						PURLType: "generic",
					},
					{
						Name:     "requests",
						Version:  "2.31.0",
						PURLType: "pypi",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "custom_target_and_keep_going_in_plugin_config",
			setupFs: func(t *testing.T, wsDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(wsDir, "MODULE.bazel"), []byte(""), 0644); err != nil {
					t.Fatalf("failed to create MODULE.bazel: %v", err)
				}
			},
			scanPath: "MODULE.bazel",
			pluginConfig: &cpb.PluginConfig{
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{
						Config: &cpb.PluginSpecificConfig_BazelAspect{
							BazelAspect: &cpb.BazelAspectConfig{
								Target:    "//src/...",
								KeepGoing: new(bool),
							},
						},
					},
				},
			},
			mockRunner: func(t *testing.T, wsDir string) aspect.CommandRunner {
				t.Helper()
				return &mockCommandRunner{
					runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
						var hasTarget, hasKeepGoing bool
						var bepPath string
						for _, arg := range args {
							if arg == "//src/..." {
								hasTarget = true
							}
							if arg == "--keep_going" {
								hasKeepGoing = true
							}
							if after, ok := strings.CutPrefix(arg, "--build_event_json_file="); ok {
								bepPath = after
							}
						}
						if !hasTarget {
							t.Errorf("missing target //src/... in args: %v", args)
						}
						if hasKeepGoing {
							t.Errorf("unexpected --keep_going in args: %v", args)
						}
						return os.WriteFile(bepPath, []byte(""), 0644)
					},
				}
			},
			wantInv: inventory.Inventory{},
			wantErr: nil,
		},
		{
			name: "bazel_not_found_in_path",
			setupFs: func(t *testing.T, wsDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(wsDir, "WORKSPACE"), []byte(""), 0644); err != nil {
					t.Fatalf("failed to create WORKSPACE: %v", err)
				}
			},
			scanPath: "WORKSPACE",
			mockRunner: func(t *testing.T, wsDir string) aspect.CommandRunner {
				t.Helper()
				return &mockCommandRunner{
					lookPathFunc: func(file string) (string, error) {
						return "", exec.ErrNotFound
					},
				}
			},
			wantErr: cmpopts.AnyError,
		},
		{
			name: "not_a_bazel_workspace",
			setupFs: func(t *testing.T, wsDir string) {
				t.Helper()
				// No WORKSPACE or MODULE.bazel file created
			},
			scanPath: "some/other/file.txt",
			mockRunner: func(t *testing.T, wsDir string) aspect.CommandRunner {
				t.Helper()
				return &mockCommandRunner{
					runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
						t.Error("bazel should not be run outside a bazel workspace")
						return nil
					},
				}
			},
			wantInv: inventory.Inventory{},
			wantErr: nil,
		},
		{
			name: "build_events_file_missing_read_error",
			setupFs: func(t *testing.T, wsDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(wsDir, "WORKSPACE"), []byte(""), 0644); err != nil {
					t.Fatalf("failed to create WORKSPACE: %v", err)
				}
			},
			scanPath: "WORKSPACE",
			mockRunner: func(t *testing.T, wsDir string) aspect.CommandRunner {
				t.Helper()
				return &mockCommandRunner{
					runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
						// Don't create the BEP file, simulating execution failure
						return errors.New("bazel build failed")
					},
				}
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wsDir := t.TempDir()
			if tt.setupFs != nil {
				tt.setupFs(t, wsDir)
			}

			runner := tt.mockRunner(t, wsDir)
			e, err := aspect.NewWithRunner(tt.pluginConfig, runner)
			if err != nil {
				t.Fatalf("aspect.NewWithRunner() error: %v", err)
			}

			got, err := e.Extract(t.Context(), &filesystem.ScanInput{
				Root: wsDir,
				Path: tt.scanPath,
			})

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Extract() unexpected error diff (-want +got):\n%s", diff)
			}

			if tt.wantErr == nil {
				if diff := cmp.Diff(tt.wantInv, got, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("Extract() inventory mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestExtractor_Extract_AlreadyProcessed(t *testing.T) {
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "WORKSPACE"), []byte(""), 0644); err != nil {
		t.Fatalf("failed to create WORKSPACE: %v", err)
	}

	var runCount int
	runner := &mockCommandRunner{
		runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
			runCount++
			for _, arg := range args {
				if after, ok := strings.CutPrefix(arg, "--build_event_json_file="); ok {
					return os.WriteFile(after, []byte(""), 0644)
				}
			}
			return nil
		},
	}

	e, err := aspect.NewWithRunner(nil, runner)
	if err != nil {
		t.Fatalf("aspect.NewWithRunner() error: %v", err)
	}

	input := &filesystem.ScanInput{
		Root: wsDir,
		Path: "WORKSPACE",
	}

	// First extraction processes the workspace
	if _, err := e.Extract(t.Context(), input); err != nil {
		t.Fatalf("first Extract() error = %v", err)
	}
	if runCount != 1 {
		t.Errorf("bazel run called %d times, want 1", runCount)
	}

	// Second extraction on the same workspace should be skipped
	got, err := e.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("second Extract() error = %v", err)
	}
	if runCount != 1 {
		t.Errorf("bazel run called %d times on second Extract(), want 1", runCount)
	}
	if len(got.Packages) != 0 {
		t.Errorf("second Extract() expected empty packages, got %v", got.Packages)
	}
}

func TestExtractor_Extract_MultipleTargets(t *testing.T) {
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "MODULE.bazel"), []byte(""), 0644); err != nil {
		t.Fatalf("failed to create MODULE.bazel: %v", err)
	}

	var capturedArgs []string
	runner := &mockCommandRunner{
		runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
			capturedArgs = args
			for _, arg := range args {
				if after, ok := strings.CutPrefix(arg, "--build_event_json_file="); ok {
					return os.WriteFile(after, []byte(""), 0644)
				}
			}
			return nil
		},
	}

	cfg := &cpb.PluginConfig{
		PluginSpecific: []*cpb.PluginSpecificConfig{
			{
				Config: &cpb.PluginSpecificConfig_BazelAspect{
					BazelAspect: &cpb.BazelAspectConfig{
						Target: "//pkg1/... //pkg2/... -//pkg3/...",
					},
				},
			},
		},
	}

	e, err := aspect.NewWithRunner(cfg, runner)
	if err != nil {
		t.Fatalf("aspect.NewWithRunner() error: %v", err)
	}

	input := &filesystem.ScanInput{
		Root: wsDir,
		Path: "MODULE.bazel",
	}

	if _, err := e.Extract(t.Context(), input); err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	// Verify that "--", "//pkg1/...", "//pkg2/...", and "-//pkg3/..." were passed as separate arguments
	dashIdx := -1
	for i, arg := range capturedArgs {
		if arg == "--" {
			dashIdx = i
			break
		}
	}
	if dashIdx == -1 {
		t.Fatalf("expected '--' separator in args: %v", capturedArgs)
	}

	gotTargets := capturedArgs[dashIdx+1:]
	wantTargets := []string{"//pkg1/...", "//pkg2/...", "-//pkg3/..."}
	if diff := cmp.Diff(wantTargets, gotTargets); diff != "" {
		t.Errorf("targets mismatch (-want +got):\n%s", diff)
	}
}

func TestExtractor_Extract_LargeBEPLine(t *testing.T) {
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "MODULE.bazel"), []byte(""), 0644); err != nil {
		t.Fatalf("failed to create MODULE.bazel: %v", err)
	}

	runner := &mockCommandRunner{
		runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
			var bepPath string
			for _, arg := range args {
				if after, ok := strings.CutPrefix(arg, "--build_event_json_file="); ok {
					bepPath = after
				}
			}
			if bepPath == "" {
				t.Fatal("missing --build_event_json_file")
			}

			outDir := filepath.Dir(bepPath)
			targetJSON := filepath.Join(outDir, "target.scalibr.json")
			data := map[string]string{
				"name":    "huge_dep",
				"version": "1.0.0",
			}
			jsonData, err := json.Marshal(data)
			if err != nil {
				return err
			}
			if err := os.WriteFile(targetJSON, jsonData, 0644); err != nil {
				return err
			}

			// Generate a line exceeding bufio.MaxScanTokenSize (64 KB), e.g. 100 KB line
			padding := strings.Repeat("x", 100*1024)
			largeLine := fmt.Sprintf(`{"id":{"namedSet":{"id":"0"}},"dummy":"%s","namedSetOfFiles":{"files":[{"uri":"file://%s"}]}}`, padding, targetJSON)

			return os.WriteFile(bepPath, []byte(largeLine), 0644)
		},
	}

	e, err := aspect.NewWithRunner(nil, runner)
	if err != nil {
		t.Fatalf("aspect.NewWithRunner() error: %v", err)
	}

	input := &filesystem.ScanInput{
		Root: wsDir,
		Path: "MODULE.bazel",
	}

	inv, err := e.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	wantPkgs := []*extractor.Package{
		{
			Name:     "huge_dep",
			Version:  "1.0.0",
			PURLType: "generic",
		},
	}
	if diff := cmp.Diff(wantPkgs, inv.Packages); diff != "" {
		t.Errorf("inventory mismatch for large BEP line (-want +got):\n%s", diff)
	}
}

func TestExtractor_Extract_NestedSubworkspaceSkipped(t *testing.T) {
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "MODULE.bazel"), []byte(""), 0644); err != nil {
		t.Fatalf("failed to create root MODULE.bazel: %v", err)
	}

	subDir := filepath.Join(wsDir, "submodule")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create submodule dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "MODULE.bazel"), []byte(""), 0644); err != nil {
		t.Fatalf("failed to create submodule MODULE.bazel: %v", err)
	}

	var runDirs []string
	runner := &mockCommandRunner{
		runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
			runDirs = append(runDirs, dir)
			for _, arg := range args {
				if after, ok := strings.CutPrefix(arg, "--build_event_json_file="); ok {
					return os.WriteFile(after, []byte(""), 0644)
				}
			}
			return nil
		},
	}

	e, err := aspect.NewWithRunner(nil, runner)
	if err != nil {
		t.Fatalf("aspect.NewWithRunner() error: %v", err)
	}

	// First scan input at root
	rootInput := &filesystem.ScanInput{
		Root: wsDir,
		Path: "MODULE.bazel",
	}
	if _, err := e.Extract(t.Context(), rootInput); err != nil {
		t.Fatalf("root Extract() error = %v", err)
	}

	// Second scan input at nested submodule
	subInput := &filesystem.ScanInput{
		Root: wsDir,
		Path: "submodule/MODULE.bazel",
	}
	got, err := e.Extract(t.Context(), subInput)
	if err != nil {
		t.Fatalf("submodule Extract() error = %v", err)
	}

	if len(runDirs) != 1 {
		t.Errorf("expected bazel to run 1 time, ran %d times in dirs: %v", len(runDirs), runDirs)
	}
	if len(got.Packages) != 0 {
		t.Errorf("expected nested submodule to return empty packages, got %v", got.Packages)
	}
}
