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
		keepGoing: false,
	}
	for _, p := range cfg.GetPluginSpecific() {
		if b := p.GetBazel(); b != nil {
			if b.GetBazelTarget() != "" {
				e.target = b.GetBazelTarget()
			}
			e.keepGoing = b.GetKeepGoing()
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
	return &plugin.Capabilities{RunningSystem: true, DirectFS: true}
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

	_, err := exec.LookPath("bazel")
	if err != nil {
		return inventory.Inventory{}, errors.New("bazel not found in PATH")
	}

	// Setup a temporary workspace package for the aspect
	aspectDir := filepath.Join(input.ScanRoot.Path, ".scalibr_aspect")
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

	args := []string{"build", "--nobuild", "--aspects=//.scalibr_aspect:scalibr_aspect.bzl%scalibr_aspect"}
	if e.keepGoing {
		args = append(args, "--keep_going")
	}
	
	// Add check_visibility=false to bypass internal access restrictions on mega targets
	args = append(args, "--check_visibility=false")
	
	// Add a unique cache-buster so Bazel always re-evaluates the aspect and prints to stderr
	uuidStr := fmt.Sprintf("%d", os.Getpid()) // good enough cache buster for single runs
	args = append(args, "--define", fmt.Sprintf("scalibr_run=%s", uuidStr))
	
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
			version = data.Version
		}
		if version == "" {
			version = data.Tag
		}
		if version == "" && len(data.Commit) >= 12 {
			version = data.Commit[:12]
		}
		if version == "" {
			version = "NOASSERTION"
		}

		url := data.PackageURL
		if url == "" {
			url = data.URL
		}
		if url == "" {
			url = data.URLs
		}
		if url == "" {
			url = data.Remote
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
			} else if strings.Contains(url, "pypi.org") {
				purlType = "pypi"
			} else if strings.Contains(url, "npmjs.org") {
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

	return inventory.Inventory{Packages: pkgs}, nil
}
