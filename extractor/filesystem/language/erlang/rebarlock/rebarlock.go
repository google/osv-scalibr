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
	"bufio"
	"bytes"
	"context"
	"fmt"
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

	// maxLineBytes bounds a single line of the lockfile. rebar3 writes short
	// lines, so anything past this is not a lockfile we want to parse.
	maxLineBytes = 1 * units.MiB

	// maxPendingBytes bounds how much of the file is held while waiting for a
	// dependency tuple that wraps across lines to complete. A tuple is a name,
	// a URL and a commit, so a few hundred bytes; this leaves a wide margin.
	maxPendingBytes = 64 * units.KiB
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
// arbitrary points, so lines are accumulated until a tuple completes rather
// than matched one at a time. Both shapes are covered because the patterns
// below anchor on the dependency tuples themselves rather than on the
// surrounding envelope.
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
	maxFileSizeBytes := defaultMaxFileSizeBytes
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
	scanner := bufio.NewScanner(input.Reader)
	scanner.Buffer(make([]byte, 0, 64*units.KiB), int(maxLineBytes))

	packages := []*extractor.Package{}

	// pending holds the lines read so far that have not yet been consumed by a
	// match, so a tuple that wraps across lines is seen whole once its last
	// line arrives. pendingLine is the 1-based line number of pending[0].
	var pending []byte
	pendingLine := 1
	lineNo := 0

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted at line %d: %w", e.Name(), lineNo, err)
		}
		lineNo++
		if len(pending) == 0 {
			pendingLine = lineNo
		}
		pending = append(pending, scanner.Bytes()...)
		pending = append(pending, '\n')

		consumed := 0
		for _, m := range pkgDepRe.FindAllSubmatchIndex(pending, -1) {
			packages = append(packages, &extractor.Package{
				Name:     string(pending[m[2]:m[3]]),
				Version:  string(pending[m[4]:m[5]]),
				PURLType: purl.TypeHex,
				Location: extractor.LocationFromPathAndLine(input.Path, pendingLine+bytes.Count(pending[:m[0]], []byte{'\n'})),
			})
			consumed = max(consumed, m[1])
		}
		// Deps pinned to a git commit are reported against the GIT ecosystem
		// rather than Hex: they are not hex.pm releases, and matching them by
		// name against Hex advisories produces false positives.
		for _, m := range gitDepRe.FindAllSubmatchIndex(pending, -1) {
			packages = append(packages, &extractor.Package{
				Name:     string(pending[m[2]:m[3]]),
				PURLType: purl.TypeGit,
				Location: extractor.LocationFromPathAndLine(input.Path, pendingLine+bytes.Count(pending[:m[0]], []byte{'\n'})),
				SourceCode: &extractor.SourceCodeIdentifier{
					Repo:   string(pending[m[4]:m[5]]),
					Commit: string(pending[m[6]:m[7]]),
				},
			})
			consumed = max(consumed, m[1])
		}

		switch {
		case consumed > 0:
			// Drop everything up to the end of the last match; a following
			// tuple may already have started on the same line.
			pendingLine += bytes.Count(pending[:consumed], []byte{'\n'})
			pending = pending[consumed:]
		case len(pending) > int(maxPendingBytes):
			// Nothing matched for a long stretch, which means we are inside the
			// attribute section or a malformed file. Keep only the tail from the
			// last point a dependency tuple could have started.
			cut := bytes.LastIndex(pending, []byte(`{<<"`))
			if cut < 0 {
				cut = len(pending)
			}
			pendingLine += bytes.Count(pending[:cut], []byte{'\n'})
			pending = pending[cut:]
		}
	}
	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read %q: %w", input.Path, err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
