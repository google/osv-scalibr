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

// Package rebarlock extracts Erlang rebar3 rebar.lock files.
package rebarlock

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "erlang/rebarlock"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB // 10 MB
)

// rebar.lock is an Erlang term file written by rebar3. It comes in two shapes:
//
//	Legacy (no Hex deps, so no attribute section):
//	  [{<<"dep">>,{git,"https://example.com/dep.git",{ref,"abc123"}},0}].
//
//	Current (a {Version, Deps} tuple followed by a pkg_hash attribute section):
//	  {"1.2.0",
//	  [{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.9.0">>},0},
//	   {<<"gradualizer">>,
//	    {git,"https://github.com/josefs/Gradualizer.git",
//	         {ref,"3021d29d82741399d131e3be38d2a8db79d146d4"}},
//	    0}]}.
//	  [
//	  {pkg_hash,[
//	   {<<"cowboy">>, <<"865DD8B6...">>}]}
//	  ].
//
// Dependency tuples are pretty-printed by Erlang's ~p and wrap across lines at
// arbitrary points, so the file is matched as a whole rather than line by line.
// Both shapes are covered because the patterns below anchor on the dependency
// tuples themselves rather than on the surrounding envelope.
var (
	// {<<"AppName">>,{pkg,<<"HexName">>,<<"Version">>}
	// AppName is the OTP application name, HexName is the package name on
	// hex.pm. They usually match but are allowed to differ, e.g.
	// {<<"uuid">>,{pkg,<<"uuid_erl">>,<<"2.0.1">>},0}. Vulnerability feeds key
	// off the hex.pm name, so HexName is the one that gets reported.
	pkgDepRe = regexp.MustCompile(`\{<<"[^"]+">>\s*,\s*\{pkg\s*,\s*<<"([^"]+)">>\s*,\s*<<"([^"]+)">>\s*\}`)

	// {<<"AppName">>,{git,"URL",{ref,"Commit"}}
	// git_subdir carries the same URL and ref, with the subdirectory appended
	// as a fourth element that does not affect vulnerability matching.
	// Mercurial deps use the same shape but a Mercurial changeset ID is not a
	// git commit, so `hg` is deliberately not matched here.
	gitDepRe = regexp.MustCompile(`\{<<"([^"]+)">>\s*,\s*\{git(?:_subdir)?\s*,\s*"([^"]*)"\s*,\s*\{ref\s*,\s*"([^"]*)"\s*\}`)
)

// Extractor extracts Erlang packages from rebar3 rebar.lock files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a rebar.lock extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := int64(defaultMaxFileSizeBytes)
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a rebar.lock file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "rebar.lock" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil || (e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes) {
		e.reportFileRequired(path, stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:   path,
		Result: result,
	})
}

// Extract parses the rebar.lock file to extract Erlang package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := e.extract(ctx, input)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inv, err
}

func (e Extractor) extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if err := ctx.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("%s halted: %w", e.Name(), err)
	}

	// FileRequired already bounds the size, but a scanner can call Extract
	// directly, so the read is capped here as well.
	reader := io.Reader(input.Reader)
	if e.maxFileSizeBytes > 0 {
		reader = io.LimitReader(reader, e.maxFileSizeBytes)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read %q: %w", input.Path, err)
	}

	location := extractor.LocationFromPath(input.Path)
	packages := []*extractor.Package{}

	for _, match := range pkgDepRe.FindAllSubmatch(content, -1) {
		packages = append(packages, &extractor.Package{
			Name:     string(match[1]),
			Version:  string(match[2]),
			PURLType: purl.TypeHex,
			Location: location,
		})
	}

	// Deps pinned to a git commit are reported against the GIT ecosystem rather
	// than Hex: they are not hex.pm releases, and matching them by name against
	// Hex advisories produces false positives.
	for _, match := range gitDepRe.FindAllSubmatch(content, -1) {
		packages = append(packages, &extractor.Package{
			Name:     string(match[1]),
			PURLType: purl.TypeGit,
			Location: location,
			SourceCode: &extractor.SourceCodeIdentifier{
				Repo:   string(match[2]),
				Commit: string(match[3]),
			},
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
