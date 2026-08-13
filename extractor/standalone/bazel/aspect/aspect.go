// Package aspect provides a standalone extractor for Bazel via aspects.
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
	"strconv"
	"strings"

	_ "embed"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

//go:embed scalibr_aspect.bzl
var scalibrAspectBzl []byte

// Name is the unique name of this extractor.
const Name = "bazel/aspect"

// Extractor is a standalone extractor for Bazel dependencies using an aspect.
type Extractor struct {
	// target is the Bazel target to run the aspect on.
	target string
	// keepGoing determines whether to use the --keep_going flag.
	keepGoing bool
}

// New returns a new instance of the Extractor.
func New(cfg *cpb.PluginConfig) (standalone.Extractor, error) {
	e := &Extractor{
		target:    "//...",
		keepGoing: true,
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

// Extract runs the bazel build command with the embedded aspect.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	if input.ScanRoot == nil || input.ScanRoot.Path == "" {
		return inventory.Inventory{}, errors.New("ScanRoot is required")
	}

	// Verify that the scan root is actually a Bazel workspace.
	// Running 'bazel build' outside of a workspace traverses parent directories
	// or fails in ways we want to avoid.
	if !isBazelWorkspace(input.ScanRoot.Path) {
		return inventory.Inventory{}, nil
	}

	_, err := exec.LookPath("bazel")
	if err != nil {
		return inventory.Inventory{}, errors.New("bazel not found in PATH")
	}

	// Setup a temporary workspace package for the aspect inside the scan root
	// so it can be referenced as a valid Bazel label.
	aspectDir, err := os.MkdirTemp(input.ScanRoot.Path, ".scalibr_aspect_*")
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

	aspectPkg := filepath.Base(aspectDir)
	args := []string{"build", "--nobuild", "--aspects=//" + aspectPkg + ":scalibr_aspect.bzl%scalibr_aspect"}
	if e.keepGoing {
		args = append(args, "--keep_going")
	}

	// Map DirsToSkip blocklists into Bazel's --deleted_packages flag so it respects exclusions
	var deletedPackages []string
	for _, skipDir := range input.DirsToSkip {
		if rel, err := filepath.Rel(input.ScanRoot.Path, skipDir); err == nil && !strings.HasPrefix(rel, "..") && rel != "." {
			deletedPackages = append(deletedPackages, filepath.ToSlash(rel))
		}
	}
	if len(deletedPackages) > 0 {
		args = append(args, "--deleted_packages="+strings.Join(deletedPackages, ","))
	}

	// Add check_visibility=false to bypass internal access restrictions on mega targets
	args = append(args, "--check_visibility=false")

	// Add a unique cache-buster so Bazel always re-evaluates the aspect and prints to stderr
	uuidStr := strconv.Itoa(os.Getpid()) // good enough cache buster for single runs
	args = append(args, "--define", "scalibr_run="+uuidStr)

	args = append(args, e.target)

	cmd := exec.CommandContext(ctx, "bazel", args...)
	cmd.Dir = input.ScanRoot.Path

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Ignore the execution error since --nobuild or missing visibility might fail the build,
	// but the analysis phase prints what we need.
	_ = cmd.Run()

	scanner := bufio.NewScanner(&stderr)
	packagesMap := make(map[string]*extractor.Package)

	for scanner.Scan() {
		line := scanner.Text()
		prefix := "SCALIBR_ASPECT_DATA::"
		_, jsonStr, found := strings.Cut(line, prefix)
		if !found {
			continue
		}

		var data aspectData
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
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
		// Clean up the name if it starts with @ or +
		pkgName = strings.TrimLeft(pkgName, "@+")

		normName := normalizeModuleName(pkgName)
		if strings.HasPrefix(pkgName, "gazelle") {
			goName := getGoPkgNameFromURL(url)
			if goName != "" {
				pkgName = goName
				purlType = "golang"
			} else {
				pkgName = normName
			}
		} else if strings.HasPrefix(pkgName, "crates_") {
			pkgName = strings.Split(pkgName, "__")[len(strings.Split(pkgName, "__"))-1]
			pkgName = strings.Split(pkgName, "-")[0]
			purlType = "cargo"
		} else {
			pkgName = normName
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
