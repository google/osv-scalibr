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

// Package aspect provides a filesystem extractor for Bazel via aspects.
package aspect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	_ "embed"

	"sync"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

//go:embed scalibr_aspect.bzl
var scalibrAspectBzl []byte

// Name is the unique name of this extractor.
const Name = "bazel/aspect"

// CommandRunner abstracts command execution for testing.
type CommandRunner interface {
	LookPath(file string) (string, error)
	Run(ctx context.Context, dir string, name string, args ...string) error
}

type defaultCommandRunner struct{}

func (r *defaultCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (r *defaultCommandRunner) Run(ctx context.Context, dir string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Bazel analysis succeeds in generating the aspect output even if the build phase fails or --nobuild is used.
	_ = cmd.Run()
	return nil
}

// Extractor is a filesystem extractor for Bazel dependencies using an aspect.
type Extractor struct {
	// target is the Bazel target to run the aspect on.
	target string
	// keepGoing determines whether to use the --keep_going flag.
	keepGoing bool
	// processed tracks workspace roots that have already been processed to avoid duplicate executions.
	processed sync.Map
	// runner executes system commands.
	runner CommandRunner
}

// New returns a new instance of the Extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return NewWithRunner(cfg, &defaultCommandRunner{})
}

// NewWithRunner returns a new instance of the Extractor with a custom CommandRunner.
func NewWithRunner(cfg *cpb.PluginConfig, runner CommandRunner) (filesystem.Extractor, error) {
	e := &Extractor{
		target:    "//...",
		keepGoing: true,
		runner:    runner,
	}

	for _, specific := range cfg.GetPluginSpecific() {
		if bazelCfg := specific.GetBazelAspect(); bazelCfg != nil {
			if bazelCfg.GetTarget() != "" {
				e.target = bazelCfg.GetTarget()
			}
			if bazelCfg.KeepGoing != nil {
				e.keepGoing = *bazelCfg.KeepGoing
			}
		}
	}
	return e, nil
}

// Name returns the extractor's name.
func (e *Extractor) Name() string { return Name }

// Version returns the extractor's version.
func (e *Extractor) Version() int { return 0 }

// Requirements returns the requirements for this extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	// This plugin requires AllowUnsafePlugins because it actively invokes the `bazel build` command
	// which executes arbitrary macros, actions, and repository rules on the host machine.
	return &plugin.Capabilities{RunningSystem: true, DirectFS: true, AllowUnsafePlugins: true}
}

// aspectData represents the JSON structure output by the Bazel aspect.
type aspectData struct {
	// Name is the workspace name.
	Name string `json:"name"`
	// Label is the bazel target label.
	Label string `json:"label"`
	// Kind is the bazel rule kind.
	Kind string `json:"kind"`
	// Version is the package version.
	Version string `json:"version"`
	// Tag is the source control tag.
	Tag string `json:"tag"`
	// Commit is the source control commit.
	Commit string `json:"commit"`
	// URL is the primary URL.
	URL string `json:"url"`
	// URLs contains a list of URLs.
	URLs string `json:"urls"`
	// StripPrefix is the bazel rule strip_prefix.
	StripPrefix string `json:"strip_prefix"`
	// Remote is the source control remote.
	Remote string `json:"remote"`
	// PackageName is the rules_license package_name attribute.
	PackageName string `json:"package_name"`
	// PackageVersion is the rules_license package_version attribute.
	PackageVersion string `json:"package_version"`
	// PackageURL is the rules_license package_url attribute.
	PackageURL string `json:"package_url"`
}

// FileRequired returns true if the file is a Bazel workspace marker.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())
	return base == "WORKSPACE" || base == "WORKSPACE.bazel" || base == "MODULE.bazel"
}

// Extract runs the bazel build command with the embedded aspect.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	workspaceRoot := filepath.Dir(filepath.Join(input.Root, input.Path))

	// Check if we already processed this workspace root
	if _, loaded := e.processed.LoadOrStore(workspaceRoot, true); loaded {
		return inventory.Inventory{}, nil
	}

	// Verify that the scan root is actually a Bazel workspace.
	// Running 'bazel build' outside of a workspace traverses parent directories
	// or fails in ways we want to avoid.
	if !isBazelWorkspace(workspaceRoot) {
		return inventory.Inventory{}, nil
	}

	if e.runner == nil {
		e.runner = &defaultCommandRunner{}
	}

	_, err := e.runner.LookPath("bazel")
	if err != nil {
		return inventory.Inventory{}, errors.New("bazel not found in PATH")
	}

	aspectDir, err := os.MkdirTemp(workspaceRoot, ".scalibr_aspect_*")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(aspectDir)

	if err := os.WriteFile(filepath.Join(aspectDir, "BUILD.bazel"), []byte(""), 0644); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to write BUILD.bazel: %w", err)
	}

	if err := os.WriteFile(filepath.Join(aspectDir, "scalibr_aspect.bzl"), scalibrAspectBzl, 0644); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to write aspect file: %w", err)
	}

	eventsFile, err := os.MkdirTemp("", "bazel_events")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create events dir: %w", err)
	}
	defer os.RemoveAll(eventsFile)
	bepPath := filepath.Join(eventsFile, "events.json")

	aspectPkg := filepath.Base(aspectDir)
	args := []string{"build", "--aspects=//" + aspectPkg + ":scalibr_aspect.bzl%scalibr_aspect", "--output_groups=scalibr_out"}
	if e.keepGoing {
		args = append(args, "--keep_going")
	}
	args = append(args, "--build_event_json_file="+bepPath)

	// Add check_visibility=false to bypass internal access restrictions on mega targets
	args = append(args, "--check_visibility=false")

	args = append(args, e.target)

	_ = e.runner.Run(ctx, workspaceRoot, "bazel", args...)

	packagesMap := make(map[string]*extractor.Package)

	bepData, err := os.ReadFile(bepPath)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read build events: %w", err)
	}

	// Simple extraction of all file URIs ending with .scalibr.json from BEP JSON stream
	scanner := bufio.NewScanner(bytes.NewReader(bepData))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, ".scalibr.json") {
			continue
		}
		// Look for "uri":"file://..."
		prefix := `"uri":"file://`
		idx := strings.Index(line, prefix)
		if idx == -1 {
			continue
		}
		startIdx := idx + len(prefix)
		endIdx := strings.Index(line[startIdx:], `"`)
		if endIdx == -1 {
			continue
		}
		filePath := line[startIdx : startIdx+endIdx]

		fileData, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		var data aspectData
		if err := json.Unmarshal(fileData, &data); err != nil {
			continue
		}

		// Use package_name as the primary identifier if available
		dedupKey := data.Name
		if data.PackageName != "" {
			dedupKey = data.PackageName
		}

		if _, exists := packagesMap[dedupKey]; exists {
			continue
		}

		version := data.PackageVersion
		if version == "" {
			version = cleanVersion(data.Version)
		}
		if version == "" {
			version = cleanVersion(data.Tag)
		}

		url := data.PackageURL
		if url == "" {
			url = data.URL
		}
		if url == "" && data.URLs != "" {
			// Just take the first URL if it's a JSON array or comma separated
			url = strings.Trim(strings.Split(data.URLs, ",")[0], " []\"")
		}
		if url == "" {
			url = data.Remote
		}

		if version == "" {
			version = extractVersionFromURL(url)
		}
		if version == "" && data.StripPrefix != "" {
			version = extractVersionFromStripPrefix(data.StripPrefix)
		}
		if version == "" && len(data.Commit) >= 12 {
			version = data.Commit[:12]
		}
		if version == "" {
			version = "NOASSERTION"
		}

		purlType := "generic"
		// If it's a standard PURL (pkg:type/name@version), extract the type
		if strings.HasPrefix(data.PackageURL, "pkg:") {
			parts := strings.Split(data.PackageURL, ":")
			if len(parts) > 1 {
				purlType = strings.Split(parts[1], "/")[0]
			}
		} else {
			if strings.Contains(url, "github.com") {
				purlType = "github"
			} else if strings.Contains(url, "pypi.org") || strings.Contains(url, "python.pkg.dev") {
				purlType = "pypi"
			} else if strings.Contains(url, "npmjs.org") || strings.Contains(url, "npm.pkg.dev") {
				purlType = "npm"
			} else if strings.Contains(url, "crates.io") {
				purlType = "cargo"
			}
		}

		pkgName := data.PackageName
		if pkgName == "" {
			pkgName = data.Name
		}
		pkgName = strings.TrimLeft(pkgName, "@+")

		normName := normalizeModuleName(pkgName)
		pkgName = parseBzlmodName(normName, &purlType)

		if strings.HasPrefix(data.Name, "gazelle") || strings.HasPrefix(pkgName, "gazelle") || strings.HasPrefix(normName, "com_github") {
			goName := getGoPkgNameFromURL(url)
			if goName != "" {
				pkgName = goName
				purlType = "golang"
			}
		}

		packagesMap[dedupKey] = &extractor.Package{
			Name:     pkgName,
			Version:  version,
			PURLType: purlType,
		}
	}

	var pkgs []*extractor.Package
	for _, pkg := range packagesMap {
		pkgs = append(pkgs, pkg)
	}

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})

	return inventory.Inventory{Packages: pkgs}, nil
}

// isBazelWorkspace checks if the given path contains a Bazel workspace indicator.
func isBazelWorkspace(path string) bool {
	markers := []string{"WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"}
	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(path, marker)); err == nil {
			return true
		}
	}
	return false
}
