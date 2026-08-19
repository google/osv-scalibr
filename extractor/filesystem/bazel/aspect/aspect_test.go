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
			name:      "workspace.bazel",
			inputPath: "WORKSPACE.bazel",
			want:      true,
		},
		{
			name:      "module.bazel",
			inputPath: "MODULE.bazel",
			want:      true,
		},
		{
			name:      "build",
			inputPath: "BUILD",
			want:      false,
		},
		{
			name:      "build.bazel",
			inputPath: "BUILD.bazel",
			want:      false,
		},
		{
			name:      "nested workspace",
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
		wantErr      bool
	}{
		{
			name: "success with mixed dependency types and deduplication",
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
								Name:    "npm__at_babel_core",
								Label:   "@@npm__at_babel_core//:package",
								Kind:    "npm_package",
								Version: "7.22.0",
							},
							{
								Name:    "crates__serde-1.0.188",
								Label:   "@@crates__serde-1.0.188//:serde",
								Kind:    "rust_library",
								Version: "1.0.188",
							},
							{
								Name:    "pip__requests",
								Label:   "@@pip__requests//:pkg",
								Kind:    "py_library",
								Version: "2.31.0",
							},
							{
								Name:    "gazelle~go_deps~com_github_google_uuid",
								Label:   "@gazelle~go_deps~com_github_google_uuid//:uuid",
								Kind:    "go_library",
								Version: "v1.3.0",
								URL:     "https://github.com/google/uuid/archive/v1.3.0.tar.gz",
							},
							{
								Name:           "custom_lib",
								Label:          "//libs:custom",
								Kind:           "cc_library",
								PackageName:    "my-awesome-lib",
								PackageVersion: "2.1.0",
								PackageURL:     "pkg:generic/my-awesome-lib@2.1.0",
							},
							{
								Name:        "libpng",
								Label:       "@libpng//:libpng",
								Kind:        "http_archive",
								StripPrefix: "libpng-1.6.39",
							},
							{
								Name:  "zlib",
								Label: "@zlib//:zlib",
								Kind:  "http_archive",
								URL:   "https://zlib.net/zlib-1.2.13.tar.gz",
							},
							{
								Name:   "abseil_cpp",
								Label:  "@abseil_cpp//:abseil",
								Kind:   "git_repository",
								Commit: "20230802.1-40charsha0123456789abcdef012345",
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
								Name:  "local_toolchain",
								Label: "@local_toolchain//:toolchain",
								Kind:  "cc_toolchain",
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
						Name:     "@babel/core",
						Version:  "7.22.0",
						PURLType: "npm",
					},
					{
						Name:     "abseil_cpp",
						Version:  "20230802.1-4",
						PURLType: "generic",
					},
					{
						Name:     "github.com/google/uuid",
						Version:  "1.3.0",
						PURLType: "golang",
					},
					{
						Name:     "libpng",
						Version:  "1.6.39",
						PURLType: "generic",
					},
					{
						Name:     "local_toolchain",
						Version:  "NOASSERTION",
						PURLType: "generic",
					},
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
					{
						Name:     "serde",
						Version:  "1.0.188",
						PURLType: "cargo",
					},
					{
						Name:     "zlib",
						Version:  "1.2.13",
						PURLType: "generic",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "custom target and keep_going in plugin config",
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
			wantErr: false,
		},
		{
			name: "bazel not found in PATH",
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
			wantErr: true,
		},
		{
			name: "not a bazel workspace",
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
			wantErr: false,
		},
		{
			name: "workspace already processed",
			setupFs: func(t *testing.T, wsDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(wsDir, "WORKSPACE"), []byte(""), 0644); err != nil {
					t.Fatalf("failed to create WORKSPACE: %v", err)
				}
			},
			scanPath: "WORKSPACE",
			mockRunner: func(t *testing.T, wsDir string) aspect.CommandRunner {
				t.Helper()
				var runCount int
				return &mockCommandRunner{
					runFunc: func(ctx context.Context, dir string, name string, args ...string) error {
						runCount++
						if runCount > 1 {
							t.Errorf("bazel run called %d times, want 1", runCount)
						}
						var bepPath string
						for _, arg := range args {
							if after, ok := strings.CutPrefix(arg, "--build_event_json_file="); ok {
								bepPath = after
							}
						}
						return os.WriteFile(bepPath, []byte(""), 0644)
					},
				}
			},
			wantInv: inventory.Inventory{},
			wantErr: false,
		},
		{
			name: "build events file missing / read error",
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
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wsDir := t.TempDir()
			if tt.setupFs != nil {
				tt.setupFs(t, wsDir)
			}

			cfg := tt.pluginConfig
			if cfg == nil {
				cfg = &cpb.PluginConfig{}
			}

			var runner aspect.CommandRunner
			if tt.mockRunner != nil {
				runner = tt.mockRunner(t, wsDir)
			}

			e, err := aspect.NewWithRunner(cfg, runner)
			if err != nil {
				t.Fatalf("aspect.NewWithRunner() error: %v", err)
			}

			got, err := e.Extract(context.Background(), &filesystem.ScanInput{
				Root: wsDir,
				Path: tt.scanPath,
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("Extract() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if diff := cmp.Diff(tt.wantInv, got, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("Extract() inventory mismatch (-want +got):\n%s", diff)
				}

				// If testing already-processed scenario, call Extract again
				if tt.name == "workspace already processed" {
					got2, err2 := e.Extract(context.Background(), &filesystem.ScanInput{
						Root: wsDir,
						Path: tt.scanPath,
					})
					if err2 != nil {
						t.Errorf("second Extract() unexpected error: %v", err2)
					}
					if len(got2.Packages) != 0 {
						t.Errorf("second Extract() expected empty packages, got %v", got2.Packages)
					}
				}
			}
		})
	}
}
