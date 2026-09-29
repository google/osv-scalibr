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
	"slices"
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
	outputFunc   func(ctx context.Context, dir string, name string, args ...string) ([]byte, error)
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

func (m *mockCommandRunner) Output(ctx context.Context, dir string, name string, args ...string) ([]byte, error) {
	if m.outputFunc != nil {
		return m.outputFunc(ctx, dir, name, args...)
	}
	// A module graph without dependencies.
	return []byte(`{"key":"<root>","name":"root","version":"","root":true}`), nil
}

// bepPathFromArgs returns the value of the --build_event_json_file flag.
func bepPathFromArgs(t *testing.T, args []string) string {
	t.Helper()
	for _, arg := range args {
		if after, ok := strings.CutPrefix(arg, "--build_event_json_file="); ok {
			return after
		}
	}
	t.Fatalf("missing --build_event_json_file in args: %v", args)
	return ""
}

// targetsFromArgs returns the target patterns passed after "--".
func targetsFromArgs(t *testing.T, args []string) []string {
	t.Helper()
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	t.Fatalf("missing -- in args: %v", args)
	return nil
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
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

func TestExtractor_Extract_BuildArgs(t *testing.T) {
	wsDir := t.TempDir()
	writeFile(t, filepath.Join(wsDir, "WORKSPACE"), "")

	var gotArgs []string
	runner := &mockCommandRunner{
		runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
			gotArgs = args
			// The aspect must be available in the workspace while bazel runs.
			if _, err := os.Stat(filepath.Join(dir, ".scalibr_aspect", "scalibr_aspect.bzl")); err != nil {
				t.Errorf("aspect file missing during the build: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, ".scalibr_aspect", "BUILD.bazel")); err != nil {
				t.Errorf("aspect BUILD file missing during the build: %v", err)
			}
			return os.WriteFile(bepPathFromArgs(t, args), nil, 0644)
		},
	}
	cfg := &cpb.PluginConfig{
		PluginSpecific: []*cpb.PluginSpecificConfig{{
			Config: &cpb.PluginSpecificConfig_BazelAspect{
				BazelAspect: &cpb.BazelAspectConfig{Target: " //pkg1/...  //pkg2/... -//pkg3/... "},
			},
		}},
	}
	e, err := aspect.NewWithRunner(cfg, runner)
	if err != nil {
		t.Fatalf("aspect.NewWithRunner() error: %v", err)
	}
	if _, err := e.Extract(t.Context(), &filesystem.ScanInput{Root: wsDir, Path: "WORKSPACE"}); err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	for _, want := range []string{
		"build",
		"--aspects=//.scalibr_aspect:scalibr_aspect.bzl%scalibr_aspect",
		"--output_groups=scalibr_out",
		"--norun_validations",
		"--experimental_convenience_symlinks=ignore",
		"--keep_going",
	} {
		if !slices.Contains(gotArgs, want) {
			t.Errorf("bazel args %v don't contain %q", gotArgs, want)
		}
	}
	wantTargets := []string{"//pkg1/...", "//pkg2/...", "-//pkg3/..."}
	if diff := cmp.Diff(wantTargets, targetsFromArgs(t, gotArgs)); diff != "" {
		t.Errorf("bazel targets mismatch (-want +got):\n%s", diff)
	}
	if _, err := os.Stat(filepath.Join(wsDir, ".scalibr_aspect")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("aspect directory wasn't removed after the build, Stat() error: %v", err)
	}
}

func TestExtractor_Extract_Ecosystems(t *testing.T) {
	type record = map[string]string
	records := []record{
		// Bazel module whose version comes from the module graph.
		{"name": "grpc+", "label": "@@grpc+//:grpc", "kind": "cc_library"},
		// rules_python sets the coordinates on different targets of the same repository.
		{"name": "rules_python++pip+pypi_311_numpy", "label": "@@rules_python++pip+pypi_311_numpy//:pkg", "kind": "py_library", "pypi_name": "numpy", "pypi_version": "1.26.4"},
		{"name": "rules_python++pip+pypi_311_numpy", "label": "@@rules_python++pip+pypi_311_numpy//:whl", "kind": "filegroup", "pypi_name": "numpy"},
		// The same package fetched for another Python version.
		{"name": "rules_python++pip+pypi_312_numpy", "label": "@@rules_python++pip+pypi_312_numpy//:pkg", "kind": "py_library", "pypi_name": "numpy", "pypi_version": "1.26.4"},
		// rules_js versions carry the resolved peer dependencies.
		{"name": "aspect_rules_js++npm+npm__at_angular_core__22.2.0", "label": "@@aspect_rules_js++npm+npm__at_angular_core__22.2.0//:pkg", "kind": "npm_package_internal", "package": "@angular/core", "version": "22.2.0(@angular/compiler@22.2.0)"},
		// A rules_jvm_external repository contains several artifacts.
		{"name": "rules_jvm_external++maven+maven", "label": "@@rules_jvm_external++maven+maven//:com_google_guava_guava", "kind": "jvm_import", "maven_coordinates": "com.google.guava:guava:33.0.0-jre"},
		{"name": "rules_jvm_external++maven+maven", "label": "@@rules_jvm_external++maven+maven//:junit_junit", "kind": "jvm_import", "maven_coordinates": "junit:junit:4.13.2"},
		// rules_rust crate names can contain dashes and digits.
		{"name": "rules_rust++crate+crates__proc-macro2-1.0.86", "label": "@@rules_rust++crate+crates__proc-macro2-1.0.86//:proc_macro2", "kind": "rust_library", "version": "1.0.86"},
		// Repositories generated by Bazel itself aren't dependencies.
		{"name": "bazel_tools", "label": "@@bazel_tools//tools/cpp:malloc", "kind": "cc_library"},
		{"name": "local_config_cc", "label": "@@local_config_cc//:toolchain", "kind": "cc_toolchain_suite"},
	}

	wsDir := t.TempDir()
	writeFile(t, filepath.Join(wsDir, "MODULE.bazel"), "")
	execRoot := t.TempDir()

	runner := &mockCommandRunner{
		runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
			// With a remote cache, the BEP contains bytestream:// URIs even for files that only exist
			// locally. The extractor has to resolve them relative to the exec root.
			var files []string
			for i, r := range records {
				data, err := json.Marshal(r)
				if err != nil {
					t.Fatalf("json.Marshal(): %v", err)
				}
				name := fmt.Sprintf("external/repo/target_%d.scalibr.json", i)
				writeFile(t, filepath.Join(execRoot, "bazel-out", "k8-fastbuild", "bin", filepath.FromSlash(name)), string(data))
				files = append(files, fmt.Sprintf(`{"name":%q,"uri":"bytestream://remote.example.com/blobs/%d/1","pathPrefix":["bazel-out","k8-fastbuild","bin"]}`, name, i))
			}
			// Single events can be megabytes long, e.g. the expanded target pattern of a large
			// workspace, and come before the file sets.
			hugeEvent := fmt.Sprintf(`{"id":{"pattern":{"pattern":["//..."]}},"expanded":{"targets":[%q]}}`, strings.Repeat("x", 5<<20))
			bep := strings.Join([]string{
				`{"id":{"started":{}},"started":{"uuid":"1"}}`,
				hugeEvent,
				fmt.Sprintf(`{"id":{"workspace":{}},"workspaceInfo":{"localExecRoot":%q}}`, execRoot),
				`{"id":{"namedSet":{"id":"0"}},"namedSetOfFiles":{"files":[` + strings.Join(files, ",") + `]}}`,
				// Other outputs are ignored.
				`{"id":{"namedSet":{"id":"1"}},"namedSetOfFiles":{"files":[{"name":"lib.a","uri":"bytestream://remote.example.com/blobs/x/1","pathPrefix":["bazel-out","k8-fastbuild","bin"]}]}}`,
			}, "\n")
			return os.WriteFile(bepPathFromArgs(t, args), []byte(bep), 0644)
		},
		outputFunc: func(ctx context.Context, dir string, name string, args ...string) ([]byte, error) {
			if diff := cmp.Diff([]string{"mod", "graph", "--output=json"}, args); diff != "" {
				t.Errorf("unexpected bazel mod args (-want +got):\n%s", diff)
			}
			return []byte(`{"key":"<root>","name":"root","version":"","root":true,"dependencies":[{"key":"grpc@1.74.1","name":"grpc","version":"1.74.1","apparentName":"grpc","dependencies":[]}]}`), nil
		},
	}
	e, err := aspect.NewWithRunner(nil, runner)
	if err != nil {
		t.Fatalf("aspect.NewWithRunner() error: %v", err)
	}
	got, err := e.Extract(t.Context(), &filesystem.ScanInput{Root: wsDir, Path: "MODULE.bazel"})
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	want := inventory.Inventory{Packages: []*extractor.Package{
		{Name: "@angular/core", Version: "22.2.0", PURLType: "npm"},
		{Name: "com.google.guava:guava", Version: "33.0.0-jre", PURLType: "maven"},
		{Name: "grpc", Version: "1.74.1", PURLType: "generic"},
		{Name: "junit:junit", Version: "4.13.2", PURLType: "maven"},
		{Name: "numpy", Version: "1.26.4", PURLType: "pypi"},
		{Name: "proc-macro2", Version: "1.0.86", PURLType: "cargo"},
	}}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Extract() inventory mismatch (-want +got):\n%s", diff)
	}
}

func TestExtractor_Extract_ModGraphFailureIsNotFatal(t *testing.T) {
	wsDir := t.TempDir()
	writeFile(t, filepath.Join(wsDir, "MODULE.bazel"), "")
	outDir := t.TempDir()
	runner := &mockCommandRunner{
		runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
			p := filepath.Join(outDir, "a.scalibr.json")
			writeFile(t, p, `{"name":"rules_foo+","label":"@@rules_foo+//:foo","kind":"cc_library","version":"1.2.3"}`)
			bep := fmt.Sprintf(`{"id":{"namedSet":{"id":"0"}},"namedSetOfFiles":{"files":[{"name":"a.scalibr.json","uri":"file://%s"}]}}`, filepath.ToSlash(p))
			// A failed build still produces the aspect's outputs.
			if err := os.WriteFile(bepPathFromArgs(t, args), []byte(bep), 0644); err != nil {
				return err
			}
			return errors.New("build failed")
		},
		outputFunc: func(ctx context.Context, dir string, name string, args ...string) ([]byte, error) {
			return nil, errors.New("mod graph failed")
		},
	}
	e, err := aspect.NewWithRunner(nil, runner)
	if err != nil {
		t.Fatalf("aspect.NewWithRunner() error: %v", err)
	}
	got, err := e.Extract(t.Context(), &filesystem.ScanInput{Root: wsDir, Path: "MODULE.bazel"})
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}
	want := inventory.Inventory{Packages: []*extractor.Package{
		{Name: "rules_foo", Version: "1.2.3", PURLType: "generic"},
	}}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Extract() inventory mismatch (-want +got):\n%s", diff)
	}
}

func TestExtractor_Extract_NestedWorkspaces(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "MODULE.bazel"), "")
	writeFile(t, filepath.Join(root, ".bazelignore"), "# Independent modules.\nthird_party/independent\n\nother/nested/\n")
	// Built as ordinary packages of the root workspace.
	writeFile(t, filepath.Join(root, "sub", "MODULE.bazel"), "")
	writeFile(t, filepath.Join(root, "sub", "deeper", "WORKSPACE"), "")
	// Excluded from the root workspace, so it needs its own build.
	writeFile(t, filepath.Join(root, "third_party", "independent", "MODULE.bazel"), "")
	writeFile(t, filepath.Join(root, "third_party", "independent", "WORKSPACE"), "")
	// Contains an excluded directory, so its packages can't all be built from the root.
	writeFile(t, filepath.Join(root, "other", "MODULE.bazel"), "")

	builds := make(map[string][]string)
	runner := &mockCommandRunner{
		runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				t.Fatalf("filepath.Rel(): %v", err)
			}
			if _, ok := builds[rel]; ok {
				t.Errorf("workspace %q built more than once", rel)
			}
			builds[rel] = targetsFromArgs(t, args)
			return os.WriteFile(bepPathFromArgs(t, args), nil, 0644)
		},
	}
	cfg := &cpb.PluginConfig{
		PluginSpecific: []*cpb.PluginSpecificConfig{{
			Config: &cpb.PluginSpecificConfig_BazelAspect{
				BazelAspect: &cpb.BazelAspectConfig{Target: "//src/..."},
			},
		}},
	}
	e, err := aspect.NewWithRunner(cfg, runner)
	if err != nil {
		t.Fatalf("aspect.NewWithRunner() error: %v", err)
	}

	// Nested workspaces are found before the root one, so the result mustn't depend on the order.
	for _, p := range []string{
		"sub/deeper/WORKSPACE",
		"sub/MODULE.bazel",
		"third_party/independent/WORKSPACE",
		"third_party/independent/MODULE.bazel",
		"other/MODULE.bazel",
		"MODULE.bazel",
	} {
		if _, err := e.Extract(t.Context(), &filesystem.ScanInput{Root: root, Path: filepath.FromSlash(p)}); err != nil {
			t.Fatalf("Extract(%s) error: %v", p, err)
		}
	}

	want := map[string][]string{
		// The configured targets only apply to the top-level workspace.
		".": {"//src/..."},
		filepath.FromSlash("third_party/independent"): {"//..."},
		"other": {"//..."},
	}
	if diff := cmp.Diff(want, builds); diff != "" {
		t.Errorf("bazel builds mismatch (-want +got):\n%s", diff)
	}
}
