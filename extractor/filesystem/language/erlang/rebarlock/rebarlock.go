// Package rebarlock extracts Erlang rebar.lock files.
package rebarlock

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "erlang/rebarlock"
)

var (
	pkgDependencyRe = regexp.MustCompile(`\{\s*<<"([^"]+)">>,\s*\{pkg,\s*<<"([^"]+)">>,\s*<<"([^"]+)">>(?:,\s*<<"[^"]*">>){0,2}\s*\},\s*\d+\s*\}`)
	gitDependencyRe = regexp.MustCompile(`\{\s*<<"([^"]+)">>,\s*\{git,\s*"([^"]+)",\s*\{ref,\s*"([^"]+)"\}\s*\},\s*\d+\s*\}`)
)

type pkgKey struct {
	name    string
	version string
	commit  string
}

// Extractor extracts packages from rebar.lock files.
type Extractor struct{}

// New returns a new instance of this Extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a rebar.lock file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "rebar.lock"
}

// Extract extracts packages from Erlang rebar.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	contentBytes, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read %s: %w", input.Path, err)
	}
	content := string(contentBytes)

	var packages []*extractor.Package
	seen := map[pkgKey]bool{}

	for _, match := range pkgDependencyRe.FindAllStringSubmatchIndex(content, -1) {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{Packages: packages}, fmt.Errorf("erlang/rebarlock halted due to context error: %w", err)
		}

		name := content[match[4]:match[5]]
		version := content[match[6]:match[7]]
		key := pkgKey{name: name, version: version}
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeHex,
			Location: extractor.LocationFromPathAndLine(input.Path, lineNumber(content, match[0])),
		})
	}

	for _, match := range gitDependencyRe.FindAllStringSubmatchIndex(content, -1) {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{Packages: packages}, fmt.Errorf("erlang/rebarlock halted due to context error: %w", err)
		}

		name := content[match[2]:match[3]]
		repo := content[match[4]:match[5]]
		commit := content[match[6]:match[7]]
		key := pkgKey{name: name, commit: commit}
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, &extractor.Package{
			Name:     name,
			PURLType: purl.TypeHex,
			Location: extractor.LocationFromPathAndLine(input.Path, lineNumber(content, match[0])),
			SourceCode: &extractor.SourceCodeIdentifier{
				Repo:   repo,
				Commit: commit,
			},
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

func lineNumber(content string, offset int) int {
	return strings.Count(content[:offset], "\n") + 1
}

var _ filesystem.Extractor = Extractor{}
