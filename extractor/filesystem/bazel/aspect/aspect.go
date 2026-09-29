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
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

//go:embed scalibr_aspect.bzl
var scalibrAspectBzl []byte

// Name is the unique name of this extractor.
const Name = "bazel/aspect"

const (
	// aspectPackage is the package created in the scanned workspace to hold the aspect. The name is
	// fixed so that the aspect's label is identical across runs and Bazel can reuse its analysis
	// cache.
	aspectPackage = ".scalibr_aspect"
	// defaultTarget is the target pattern used when none is configured.
	defaultTarget = "//..."
	// maxStderrBytes limits how much of Bazel's stderr is included in error messages.
	maxStderrBytes = 4096
)

// CommandRunner abstracts command execution for testing.
type CommandRunner interface {
	LookPath(file string) (string, error)
	// Run runs the command and returns an error if it fails.
	Run(ctx context.Context, dir string, name string, args ...string) error
	// Output runs the command and returns its stdout.
	Output(ctx context.Context, dir string, name string, args ...string) ([]byte, error)
}

type defaultCommandRunner struct{}

func (r *defaultCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (r *defaultCommandRunner) Run(ctx context.Context, dir string, name string, args ...string) error {
	_, err := r.Output(ctx, dir, name, args...)
	return err
}

func (r *defaultCommandRunner) Output(ctx context.Context, dir string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w; stderr (truncated): %s", err, tail(stderr.String(), maxStderrBytes))
	}
	return stdout.Bytes(), nil
}

// tail returns at most the last n bytes of s.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// Extractor is a filesystem extractor for Bazel dependencies using an aspect.
//
// The extractor runs one bazel build per independent workspace found during the scan. Nested
// workspaces are skipped when an enclosing workspace's build already includes them, i.e. when its
// .bazelignore doesn't exclude them. The configured target patterns apply to top-level workspaces;
// independent nested workspaces are always scanned with //....
type Extractor struct {
	// targets are the Bazel target patterns to run the aspect on.
	targets []string
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
		targets:   []string{defaultTarget},
		keepGoing: true,
		runner:    runner,
	}

	for _, specific := range cfg.GetPluginSpecific() {
		if bazelCfg := specific.GetBazelAspect(); bazelCfg != nil {
			// The target can contain several whitespace-separated patterns, including negative ones
			// such as "//... -//third_party/...".
			if targets := strings.Fields(bazelCfg.GetTarget()); len(targets) > 0 {
				e.targets = targets
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
func (e *Extractor) Version() int { return 1 }

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
	// Package is the npm package name of aspect_rules_js npm_package_internal targets.
	Package string `json:"package"`
	// MavenCoordinates is the rules_jvm_external "maven_coordinates=" tag (group:artifact:version).
	MavenCoordinates string `json:"maven_coordinates"`
	// PypiName is the rules_python "pypi_name=" tag.
	PypiName string `json:"pypi_name"`
	// PypiVersion is the rules_python "pypi_version=" tag.
	PypiVersion string `json:"pypi_version"`
}

// mergeFrom fills the empty fields of d with the values from o.
func (d *aspectData) mergeFrom(o *aspectData) {
	fill := func(dst *string, src string) {
		if *dst == "" {
			*dst = src
		}
	}
	fill(&d.Name, o.Name)
	fill(&d.Label, o.Label)
	fill(&d.Kind, o.Kind)
	fill(&d.Version, o.Version)
	fill(&d.Tag, o.Tag)
	fill(&d.Commit, o.Commit)
	fill(&d.URL, o.URL)
	fill(&d.URLs, o.URLs)
	fill(&d.StripPrefix, o.StripPrefix)
	fill(&d.Remote, o.Remote)
	fill(&d.PackageName, o.PackageName)
	fill(&d.PackageVersion, o.PackageVersion)
	fill(&d.PackageURL, o.PackageURL)
	fill(&d.Package, o.Package)
	fill(&d.MavenCoordinates, o.MavenCoordinates)
	fill(&d.PypiName, o.PypiName)
	fill(&d.PypiVersion, o.PypiVersion)
}

// FileRequired returns true if the file is a Bazel workspace marker.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())
	return base == "WORKSPACE" || base == "WORKSPACE.bazel" || base == "MODULE.bazel"
}

// Extract runs the bazel build command with the embedded aspect.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	scanRoot, err := filepath.Abs(input.Root)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to resolve scan root %q: %w", input.Root, err)
	}
	workspaceRoot := filepath.Dir(filepath.Join(scanRoot, input.Path))

	// Verify that the directory is actually a Bazel workspace.
	// Running 'bazel build' outside of a workspace traverses parent directories
	// or fails in ways we want to avoid.
	if !isBazelWorkspace(workspaceRoot) {
		return inventory.Inventory{}, nil
	}

	// A workspace can contain several markers (e.g. WORKSPACE and MODULE.bazel): only process it once.
	if _, loaded := e.processed.LoadOrStore(workspaceRoot, true); loaded {
		return inventory.Inventory{}, nil
	}

	if covering := coveringWorkspace(scanRoot, workspaceRoot); covering != "" {
		log.Debugf("bazel/aspect: skipping %s, it's built as part of the workspace at %s", workspaceRoot, covering)
		return inventory.Inventory{}, nil
	}

	targets := []string{defaultTarget}
	if isTopLevelWorkspace(scanRoot, workspaceRoot) {
		targets = e.targets
	}

	if e.runner == nil {
		e.runner = &defaultCommandRunner{}
	}

	if _, err := e.runner.LookPath("bazel"); err != nil {
		return inventory.Inventory{}, errors.New("bazel not found in PATH")
	}

	aspectDir := filepath.Join(workspaceRoot, aspectPackage)
	if err := os.MkdirAll(aspectDir, 0755); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create aspect dir: %w", err)
	}
	defer os.RemoveAll(aspectDir)

	if err := os.WriteFile(filepath.Join(aspectDir, "BUILD.bazel"), []byte(""), 0644); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to write BUILD.bazel: %w", err)
	}

	if err := os.WriteFile(filepath.Join(aspectDir, "scalibr_aspect.bzl"), scalibrAspectBzl, 0644); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to write aspect file: %w", err)
	}

	eventsDir, err := os.MkdirTemp("", "bazel_events")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create events dir: %w", err)
	}
	defer os.RemoveAll(eventsDir)
	bepPath := filepath.Join(eventsDir, "events.json")

	if err := e.runner.Run(ctx, workspaceRoot, "bazel", e.buildArgs(bepPath, targets)...); err != nil {
		// Bazel analysis succeeds in generating the aspect output even if the build phase fails or
		// some targets are broken, so a failed build is not fatal.
		log.Warnf("bazel/aspect: bazel build in %s returned an error, results may be incomplete: %v", workspaceRoot, err)
	}
	if err := ctx.Err(); err != nil {
		return inventory.Inventory{}, err
	}

	bepFile, err := os.Open(bepPath)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read build events: %w", err)
	}
	defer bepFile.Close()
	paths, err := aspectOutputsFromBEP(bepFile)
	if err != nil {
		log.Warnf("bazel/aspect: failed to fully parse build events in %s, results may be incomplete: %v", workspaceRoot, err)
	}

	var records []*aspectData
	var unreadable int
	for _, p := range paths {
		fileData, err := os.ReadFile(p)
		if err != nil {
			unreadable++
			continue
		}
		var data aspectData
		if err := json.Unmarshal(fileData, &data); err != nil {
			unreadable++
			continue
		}
		records = append(records, &data)
	}
	if unreadable > 0 {
		log.Warnf("bazel/aspect: %d of %d aspect output files in %s couldn't be read", unreadable, len(paths), workspaceRoot)
	}

	return inventory.Inventory{Packages: buildPackages(records, e.moduleVersions(ctx, workspaceRoot))}, nil
}

// buildArgs returns the arguments of the bazel build command that runs the aspect.
func (e *Extractor) buildArgs(bepPath string, targets []string) []string {
	args := []string{
		"build",
		"--aspects=//" + aspectPackage + ":scalibr_aspect.bzl%scalibr_aspect",
		"--output_groups=scalibr_out",
		"--build_event_json_file=" + bepPath,
		// Validation actions run even though only the aspect's output group is requested, and can
		// trigger expensive builds of tools that are irrelevant to dependency extraction.
		"--norun_validations",
		// Don't create bazel-* convenience symlinks in the scanned source tree, where they'd be
		// picked up as packages by builds of enclosing workspaces.
		"--experimental_convenience_symlinks=ignore",
		// Add check_visibility=false to bypass internal access restrictions on mega targets
		"--check_visibility=false",
	}
	if e.keepGoing {
		args = append(args, "--keep_going")
	}
	// "--" ends the flags so that negative target patterns (e.g. -//foo/...) aren't parsed as flags.
	args = append(args, "--")
	return append(args, targets...)
}

// moduleVersions returns the versions of the Bazel modules in the workspace's resolved module
// graph. Aspects can't see the attributes of the repository rules that fetched a module, so this
// is where module versions come from.
func (e *Extractor) moduleVersions(ctx context.Context, workspaceRoot string) moduleVersions {
	if _, err := os.Stat(filepath.Join(workspaceRoot, "MODULE.bazel")); err != nil {
		// Workspaces that don't use Bzlmod have no module graph.
		return nil
	}
	out, err := e.runner.Output(ctx, workspaceRoot, "bazel", "mod", "graph", "--output=json")
	if err != nil {
		log.Warnf("bazel/aspect: failed to get the module graph of %s, module versions won't be reported: %v", workspaceRoot, err)
		return nil
	}
	mv, err := parseModGraph(out)
	if err != nil {
		log.Warnf("bazel/aspect: failed to parse the module graph of %s: %v", workspaceRoot, err)
		return nil
	}
	return mv
}

// isBazelInternalRepo reports whether the repository is generated by Bazel itself rather than
// being a third-party dependency.
func isBazelInternalRepo(name string) bool {
	return name == "bazel_tools" || strings.HasPrefix(name, "local_config_")
}

// dedupKey returns the key used to merge aspect records describing the same package.
func dedupKey(d *aspectData) string {
	// A rules_jvm_external repository contains many Maven artifacts.
	if group, artifact, _, ok := parseMavenCoordinates(d.MavenCoordinates); ok {
		return "maven:" + group + ":" + artifact
	}
	// Use package_name as the primary identifier if available
	if d.PackageName != "" {
		return d.PackageName
	}
	return d.Name
}

// buildPackages converts the aspect records into packages. Records of the same repository are
// merged first, since different targets of a repository carry different parts of its metadata.
func buildPackages(records []*aspectData, modules moduleVersions) []*extractor.Package {
	merged := make(map[string]*aspectData)
	for _, r := range records {
		if isBazelInternalRepo(r.Name) {
			continue
		}
		key := dedupKey(r)
		if m, ok := merged[key]; ok {
			m.mergeFrom(r)
		} else {
			merged[key] = r
		}
	}

	// Several repositories can resolve to the same package, e.g. wheels of one PyPI package for
	// different Python versions.
	type pkgKey struct{ purlType, name, version string }
	seen := make(map[pkgKey]bool)
	var pkgs []*extractor.Package
	for _, d := range merged {
		pkg := toPackage(d, modules)
		k := pkgKey{pkg.PURLType, pkg.Name, pkg.Version}
		if seen[k] {
			continue
		}
		seen[k] = true
		pkgs = append(pkgs, pkg)
	}

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		if pkgs[i].Version != pkgs[j].Version {
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].PURLType < pkgs[j].PURLType
	})
	return pkgs
}

// toPackage converts merged aspect metadata into a package.
func toPackage(data *aspectData, modules moduleVersions) *extractor.Package {
	// Coordinates declared by the rules that created the repository are the most reliable source.
	if group, artifact, version, ok := parseMavenCoordinates(data.MavenCoordinates); ok {
		return newPackage(group+":"+artifact, version, purl.TypeMaven)
	}
	if data.PypiName != "" {
		return newPackage(data.PypiName, data.PypiVersion, purl.TypePyPi)
	}
	if data.Package != "" && strings.HasPrefix(data.Kind, "npm_package") {
		// rules_js versions can carry the resolved peer dependencies, e.g. "1.2.3(react@18.0.0)".
		version, _, _ := strings.Cut(data.Version, "(")
		return newPackage(data.Package, version, purl.TypeNPM)
	}

	version := data.PackageVersion
	moduleName := ""
	if version == "" {
		if module, v, ok := modules.lookup(data.Name); ok {
			moduleName, version = module, v
		}
	}
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

	purlType := purl.TypeGeneric
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
			purlType = purl.TypePyPi
		} else if strings.Contains(url, "npmjs.org") || strings.Contains(url, "npm.pkg.dev") {
			purlType = purl.TypeNPM
		} else if strings.Contains(url, "crates.io") {
			purlType = purl.TypeCargo
		}
	}

	if moduleName != "" {
		return newPackage(moduleName, version, purlType)
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
			purlType = purl.TypeGolang
		}
	}

	return newPackage(pkgName, version, purlType)
}

// newPackage returns a package, using NOASSERTION for unknown versions.
func newPackage(name, version, purlType string) *extractor.Package {
	if version == "" {
		version = "NOASSERTION"
	}
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purlType,
	}
}

// parseMavenCoordinates parses "group:artifact:version" Maven coordinates. Coordinates with a
// packaging or classifier ("group:artifact:packaging[:classifier]:version") are also accepted.
func parseMavenCoordinates(coords string) (group, artifact, version string, ok bool) {
	parts := strings.Split(coords, ":")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[len(parts)-1] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[len(parts)-1], true
}
