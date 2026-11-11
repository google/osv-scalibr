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

package dpkg

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	iofs "io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/common/io/discard"
	"github.com/google/osv-scalibr/fs"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// packagesIndexPattern matches apt Packages indexes and captures the archive
// component (main, universe, contrib, ...).
var packagesIndexPattern = regexp.MustCompile(`[\w.]+(?:-[\w%-]+)?_dists_[\w.-]+_([\w+-]+)_binary-\w+_Packages(?:\.gz|\.lz4|\.zst)?$`)

// officialOrigins are the Release "Origin" values of the official distro
// archives. Non-main components (universe, contrib, ...) are only indexed when
// they come from one of these, so third-party repos stay excluded (#1857, #2610).
var officialOrigins = map[string]struct{}{
	"Debian": {},
	"Ubuntu": {},
}

const aptListDir = "var/lib/apt/lists"

// aptCache contains the set of packages listed in OS repository indexes
type aptCache struct {
	value map[string]struct{}
}

// isFromOSRepo returns true if a package is listed in a matched apt Packages index
func (a *aptCache) isFromOSRepo(pkgName string) bool {
	_, exists := a.value[pkgName]
	return exists
}

// ErrMissingAptCache is returned if the cache folder is missing, empty, or
// contains no recognizable Packages indexes.
var ErrMissingAptCache = errors.New("missing apt cache folder: " + aptListDir)

// extractAptCache extracts repository package names from var/lib/apt/lists.
// If the folder is missing, empty, or has no matching Packages indexes, it
// returns ErrMissingAptCache so callers can fall back to annotating every
// dpkg-owned path.
func extractAptCache(root *fs.ScanRoot) (*aptCache, error) {
	entries, err := iofs.ReadDir(root.FS, aptListDir)
	if err != nil {
		// if the `var/lib/apt/lists` doesn't exists which could happen for 2 reasons:
		// - the folder was deleted after installation
		// - apt is not installed
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrMissingAptCache
		}
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrMissingAptCache
	}

	// Suites ("<source>_dists_<suite>" file name prefixes) whose
	// InRelease/Release file has an official Origin.
	officialSuites := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		suite, ok := strings.CutSuffix(name, "_InRelease")
		if !ok {
			suite, ok = strings.CutSuffix(name, "_Release")
		}
		if entry.IsDir() || !ok || !strings.Contains(suite, "_dists_") {
			continue
		}
		origin, err := releaseOrigin(root.FS, filepath.Join(aptListDir, name))
		if err != nil {
			return nil, err
		}
		if _, ok := officialOrigins[origin]; ok {
			officialSuites[suite] = true
		}
	}

	cache := &aptCache{
		value: make(map[string]struct{}),
	}
	foundIndex := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()

		// skip non-Packages indexes (InRelease, Sources, lock leftovers, ...)
		m := packagesIndexPattern.FindStringSubmatchIndex(name)
		if m == nil {
			continue
		}
		foundIndex = true

		// main is indexed from any source as before; other components only
		// from official distro archives.
		component, suite := name[m[2]:m[3]], name[:m[2]-1]
		if component != "main" && !officialSuites[suite] {
			continue
		}

		if err := parseAptList(root.FS, filepath.Join(aptListDir, name), cache); err != nil {
			return nil, err
		}
	}

	// A non-empty lists dir with only auxfiles/lock/partial (no Packages
	// indexes) must be treated like a missing cache (#2610).
	if !foundIndex {
		return nil, ErrMissingAptCache
	}

	return cache, nil
}

// parseAptList opens and parses a single apt list file, updating the cache.
func parseAptList(fileSystem iofs.FS, path string, cache *aptCache) error {
	f, err := fileSystem.Open(path)
	if err != nil {
		return nil // Skip files we can't open
	}
	defer f.Close()

	reader, err := readerFromExtension(f, path)
	if err != nil {
		return err
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	scanner.Split(discard.LongLines(bufio.MaxScanTokenSize))
	for scanner.Scan() {
		line := scanner.Bytes()
		// Check if the start of this line contains a package name
		if after, ok := bytes.CutPrefix(line, []byte("Package: ")); ok {
			cache.value[string(after)] = struct{}{}
		}
	}

	return scanner.Err()
}

// releaseOrigin returns the value of the "Origin" field of an apt
// InRelease/Release file, or "" if there is none.
func releaseOrigin(fileSystem iofs.FS, path string) (string, error) {
	f, err := fileSystem.Open(path)
	if err != nil {
		return "", nil // Skip files we can't open
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(discard.LongLines(bufio.MaxScanTokenSize))
	for scanner.Scan() {
		if after, ok := bytes.CutPrefix(scanner.Bytes(), []byte("Origin: ")); ok {
			return string(bytes.TrimSpace(after)), nil
		}
	}
	return "", scanner.Err()
}

// readerFromExtension returns an io.ReadCloser depending on the file extension
func readerFromExtension(f iofs.File, name string) (io.ReadCloser, error) {
	switch {
	case strings.HasSuffix(name, ".lz4"):
		return io.NopCloser(lz4.NewReader(f)), nil
	case strings.HasSuffix(name, ".gz"):
		return gzip.NewReader(f)
	case strings.HasSuffix(name, ".zst"):
		r, err := zstd.NewReader(f)
		return io.NopCloser(r), err
	default:
		return io.NopCloser(f), nil
	}
}
