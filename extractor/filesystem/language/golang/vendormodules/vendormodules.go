// Package vendormodules extracts Go vendor/modules.txt files.
package vendormodules

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"golang.org/x/mod/semver"
)

const (
	// Name is the unique name of this extractor.
	Name = "go/vendormodules"
)

type module struct {
	name    string
	version string
	line    int
	skip    bool
}

type pkgKey struct {
	name    string
	version string
}

// Extractor extracts Go modules from vendor/modules.txt files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a Go vendor/modules.txt file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.Clean(api.Path())
	return filepath.Base(path) == "modules.txt" && filepath.Base(filepath.Dir(path)) == "vendor"
}

// Extract extracts packages from a Go vendor/modules.txt file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var packages []*extractor.Package
	seen := map[pkgKey]bool{}
	var current module

	scanner := bufio.NewScanner(input.Reader)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{Packages: packages}, fmt.Errorf("go/vendormodules halted due to context error: %w", err)
		}

		line := scanner.Text()
		if strings.HasPrefix(line, "# ") {
			current = parseModuleLine(line, lineNumber)
			continue
		}

		if current.name == "" || current.skip || strings.HasPrefix(line, "## ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 1 {
			continue
		}

		key := pkgKey{name: current.name, version: current.version}
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, &extractor.Package{
			Name:     current.name,
			Version:  current.version,
			PURLType: purl.TypeGolang,
			Location: extractor.LocationFromPathAndLine(input.Path, current.line),
		})
	}
	if err := scanner.Err(); err != nil {
		return inventory.Inventory{Packages: packages}, fmt.Errorf("could not scan %s: %w", input.Path, err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

func parseModuleLine(line string, lineNumber int) module {
	fields := strings.Fields(strings.TrimPrefix(line, "# "))
	if len(fields) < 2 {
		return module{}
	}

	name := fields[0]
	version := ""
	var rest []string
	skip := false

	if semver.IsValid(fields[1]) {
		version = strings.TrimPrefix(fields[1], "v")
		rest = fields[2:]
	} else if fields[1] == "=>" {
		rest = fields[1:]
		skip = true
	} else {
		return module{}
	}

	if len(rest) > 0 {
		if len(rest) == 3 && rest[0] == "=>" && semver.IsValid(rest[2]) {
			name = rest[1]
			version = strings.TrimPrefix(rest[2], "v")
			skip = false
		} else if rest[0] == "=>" {
			skip = true
		}
	}

	if version == "" {
		skip = true
	}
	return module{name: name, version: version, line: lineNumber, skip: skip}
}

var _ filesystem.Extractor = Extractor{}
