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

package materialize

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/internal"
)

// PackSpec is one package to download.
type PackSpec struct {
	Name    string
	Version string
}

// Tarball is one downloaded file.
type Tarball struct {
	Spec    PackSpec
	TarPath string // <tmpDir>/<npm-pack-output-name>.tgz
}

// DownloadTarballs fetches the given specs via `npm pack --json` in parallel
// chunks, tolerating per-package failures. Returns successful tarballs +
// the (name, version) pairs that couldn't be fetched.
func DownloadTarballs(ctx context.Context, tmpDir string, specs []PackSpec) ([]Tarball, []internal.FailedPackage, error) {
	if len(specs) == 0 {
		return nil, nil, nil
	}
	chunkSize := max(len(specs)/runtime.NumCPU(), 10)
	var chunks [][]PackSpec
	for i := 0; i < len(specs); i += chunkSize {
		end := min(i+chunkSize, len(specs))
		chunks = append(chunks, specs[i:end])
	}

	var (
		mu       sync.Mutex
		tarballs []Tarball
		failed   []internal.FailedPackage
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)
	for _, ch := range chunks {
		g.Go(func() error {
			got, bad := runOneChunk(gctx, tmpDir, ch)
			mu.Lock()
			tarballs = append(tarballs, got...)
			failed = append(failed, bad...)
			mu.Unlock()
			// Surface cancellation so g.Wait returns it. Without this, a
			// canceled scan returns (partial, partial, nil) and the caller
			// keeps marching through Phase 1/2 as if download succeeded.
			return gctx.Err()
		})
	}
	if err := g.Wait(); err != nil {
		return tarballs, failed, err
	}
	return tarballs, failed, nil
}

// runOneChunk runs `npm pack --json` against a chunk. If the chunk
// partially succeeds, returns the successful tarballs plus the failed
// (name, version) pairs. If nothing succeeds and the chunk has more
// than one entry, retries each individually so a single bad package
// doesn't poison the whole chunk.
func runOneChunk(ctx context.Context, tmpDir string, chunk []PackSpec) ([]Tarball, []internal.FailedPackage) {
	tbs, bad := tryPack(ctx, tmpDir, chunk)
	if len(tbs) > 0 || len(chunk) == 1 {
		return tbs, bad
	}
	// Whole-chunk failure on >1 entry: retry per-package so we can pin
	// blame on the actual culprit(s) rather than the whole chunk.
	var singles []Tarball
	var singleFails []internal.FailedPackage
	for _, s := range chunk {
		one, b := tryPack(ctx, tmpDir, []PackSpec{s})
		singles = append(singles, one...)
		singleFails = append(singleFails, b...)
	}
	return singles, singleFails
}

type npmPackEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Filename string `json:"filename"`
}

// tryPack invokes `npm pack --json` for the given chunk and returns the
// resolved tarballs plus the names of any chunk entries that didn't make
// it into npm's stdout. Failure attribution is by stdout-presence (what
// did succeed); stderr is not parsed because npm error messages aren't a
// stable contract and the substrings overlap with non-fatal warnings.
func tryPack(ctx context.Context, tmpDir string, chunk []PackSpec) ([]Tarball, []internal.FailedPackage) {
	// "--" separates flags from positional args so a malformed Name
	// starting with "-" can't be misinterpreted as an npm CLI flag.
	args := []string{"pack", "--json", "--"}
	for _, s := range chunk {
		args = append(args, fmt.Sprintf("%s@%s", s.Name, s.Version))
	}
	cmd := exec.CommandContext(ctx, "npm", args...)
	cmd.Dir = tmpDir
	// Use CombinedOutput? No — stdout has the JSON, stderr has errors.
	// Capture stdout even on non-zero exit; npm pack often writes a
	// partial JSON array when some specs resolve and others don't.
	stdout, err := cmd.Output()

	// Parse whatever JSON came back. On error this may be empty or partial.
	var entries []npmPackEntry
	if len(stdout) > 0 {
		_ = json.Unmarshal(stdout, &entries)
	}

	got := make(map[string]npmPackEntry, len(entries))
	for _, e := range entries {
		got[e.Name+"@"+e.Version] = e
	}

	tarballs := make([]Tarball, 0, len(entries))
	var failed []internal.FailedPackage
	for _, s := range chunk {
		key := s.Name + "@" + s.Version
		if e, ok := got[key]; ok {
			tarballs = append(tarballs, Tarball{
				Spec:    s,
				TarPath: filepath.Join(tmpDir, e.Filename),
			})
		} else {
			failed = append(failed, internal.FailedPackage{Name: s.Name, Version: s.Version})
		}
	}

	// If we got nothing AND the command errored, return (nil, nil) so the
	// caller falls back to per-package retries — that path may surface a
	// recoverable failure for some entries.
	if len(tarballs) == 0 && err != nil && len(chunk) > 1 {
		return nil, nil
	}
	return tarballs, failed
}
